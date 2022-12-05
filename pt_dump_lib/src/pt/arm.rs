use crate::memory::memory::MemoryView;
use crate::pt::common::{Error, PhysRange};
use super::page_range::{GenericPage, GenericPageRange};

#[derive(Copy, Clone)]
pub enum Granularity {
    Pt4k,
    Pt16k,
    Pt64k,
}

#[derive(Copy, Clone)]
pub enum ArmFlavour {
    Arm32,
    Arm64,
}

#[derive(Copy, Clone)]
pub struct ArmContext {
    flavour: ArmFlavour,
    granularity: Granularity,
    virtual_address_space_size: u8,
    top_bit: u8,
}

impl ArmContext {
    pub fn new(
        flavour: ArmFlavour,
        granularity: Granularity,
        virtual_address_space_size: u8,
        top_bit: u8,
    ) -> Self {
        Self {
            flavour: flavour,
            granularity: granularity,
            virtual_address_space_size: virtual_address_space_size,
            top_bit: top_bit,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ArmPageAttributes {
    pub xn: bool,
    pub pxn: bool,
    pub permission_bits: u8,
}

#[derive(Clone)]
pub struct ArmPageRange {
    pub va: u64,
    pub extent: u64,
    pub phys_ranges: Vec<PhysRange>,
    pub attr: ArmPageAttributes,
}

impl ArmPageRange {
    pub fn is_user_readable(&self) -> bool {
        self.attr.permission_bits == 0b11 || self.attr.permission_bits == 0b01
    }

    pub fn is_kernel_readable(&self) -> bool {
        true
    }

    pub fn is_user_writeable(&self) -> bool {
        self.attr.permission_bits == 0b01
    }

    pub fn is_kernel_writeable(&self) -> bool {
        self.attr.permission_bits == 0b01 || self.attr.permission_bits == 0b00
    }

    pub fn is_user_executable(&self) -> bool {
        !self.attr.xn
    }

    pub fn is_kernel_executable(&self) -> bool {
        !self.attr.pxn
    }

    pub fn is_extendable_by(&self, va: u64, attr: &ArmPageAttributes) -> bool {
        return self.get_va() + self.get_va_extent() == va && self.attr == *attr;
    }

    pub fn extend_by(&mut self, next_extent: u64, next_phys: u64) {
        self.extent += next_extent;
        let mut last = self.phys_ranges.last_mut().unwrap();
        if last.phys_base + last.phys_extent == next_phys {
            last.phys_extent += next_extent;
        } else if last.phys_base <= next_phys
            && (next_phys + next_extent) <= (last.phys_base + last.phys_extent)
        {
            // Don't do anything since the range is already included and the range is considered semantically the same.
            return;
        } else {
            self.phys_ranges
                .push(PhysRange::new(next_phys, next_extent))
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct LevelRangeInfo {
    bit_start_incl: u8,
    block_size: u64,
}

#[derive(Clone, Debug)]
struct LevelRanges {
    levels: Vec<LevelRangeInfo>,
}

impl LevelRanges {
    fn get_level_info(self: &Self, index: u8) -> &LevelRangeInfo {
        &self.levels[index as usize]
    }

    fn get_num_levels(&self) -> usize {
        self.levels.len()
    }
}

impl Granularity {
    fn get_block_size(self) -> usize {
        match self {
            Granularity::Pt4k => 0x1000,
            Granularity::Pt16k => 0x4000,
            Granularity::Pt64k => 0x10000,
        }
    }

    fn get_bit_start(self) -> u8 {
        match self {
            Granularity::Pt4k => 12u8,
            Granularity::Pt16k => 14u8,
            Granularity::Pt64k => 16u8,
        }
    }

    fn get_num_bits_per_level(self) -> u8 {
        match self {
            Granularity::Pt4k => 9u8,
            Granularity::Pt16k => 11u8,
            Granularity::Pt64k => 13u8,
        }
    }

    fn get_level_ranges(self, address_space_size: u8) -> LevelRanges {
        let start = self.get_bit_start();
        let bits_per_level = self.get_num_bits_per_level();
        let mut ranges = vec![];
        let mut cur = start;
        while cur < address_space_size {
            let bit_start_incl = cur;
            let bit_end_incl = std::cmp::min(cur + bits_per_level, address_space_size) - 1;
            let block_size = 1u64 << bit_start_incl;
            cur = bit_end_incl + 1u8;
            ranges.push(LevelRangeInfo {
                bit_start_incl: bit_start_incl,
                block_size: block_size,
            });
        }
        ranges.reverse();
        LevelRanges { levels: ranges }
    }
}

struct TablePointerEntry {
    va: u64,
    base_address: u64,
    xn: bool,
    pxn: bool,
    permission_bits: u8,
    level: u8,
}

fn parse_block_arm64(
    context: &ArmContext,
    memory: &mut dyn MemoryView,
    table: &TablePointerEntry,
    level_ranges: &LevelRanges,
    pages: &mut Vec<ArmPageRange>,
) -> Result<(), Error> {
    let block_size = context.granularity.get_block_size();
    let block = memory.read_block(table.base_address as usize, block_size)?;
    let level_info = level_ranges.get_level_info(table.level);

    let mask_range = |(a_inclusive, b_inclusive): (u8, u8)| {
        let mask_to_zero = |a_inclusive: u8| (1_u64 << a_inclusive) - 1_u64;
        mask_to_zero(a_inclusive) ^ mask_to_zero(b_inclusive)
    };

    let extract_bits_no_shift = |value: u64, a_inclusive: u8, b_inclusive: u8| {
        value & mask_range((a_inclusive, b_inclusive))
    };

    let block_size = 8;
    for block_index in 0..block.len() / block_size {
        let raw_entry = unsafe { *((block.as_ptr() as *const u64).add(block_index)) };
        let has_bit = |bit_loc: u8| ((raw_entry >> bit_loc) & 1_u64) == 1_u64;
        let valid = has_bit(0);
        if !valid {
            continue;
        }
        let contiguous_bit = has_bit(52);
        let table_pointer = has_bit(1); // It could be a table entry or a table descriptor.

        let va_contribution = (block_index as u64) << level_info.bit_start_incl;
        let va = table.va | va_contribution;
        let base_address = extract_bits_no_shift(raw_entry, 47, 12);

        // TODO: do we have to propagate permission bit from the parent table? Most likely yes
        if (table_pointer && contiguous_bit)
            || !table_pointer
            || (table.level + 1) as usize == level_ranges.get_num_levels()
        {
            // this is a leaf page
            let permissions = ((raw_entry >> 6) & 0x3) as u8;
            let xn = has_bit(54) || table.xn;
            let pxn = has_bit(53) || table.pxn;
            let attr = ArmPageAttributes {
                xn: xn,
                pxn: pxn,
                permission_bits: permissions,
            };
            if let Some(previous_page) = pages.last_mut() {
                if previous_page.is_extendable_by(va, &attr) {
                    previous_page.extend_by(level_info.block_size, base_address);
                    continue;
                }
            }
            let entry = ArmPageRange {
                va: va,
                extent: level_info.block_size,
                phys_ranges: vec![PhysRange::new(base_address, level_info.block_size)],
                attr: attr,
            };
            pages.push(entry);
        } else {
            // this is table
            let permissions = ((raw_entry >> 61) & 0x3) as u8;
            let xn = has_bit(60) | table.xn;
            let pxn = has_bit(59) | table.pxn;

            let table = TablePointerEntry {
                va: va,
                base_address: base_address,
                xn: xn,
                pxn: pxn,
                permission_bits: permissions,
                level: table.level + 1,
            };
            parse_block_arm64(context, memory, &table, level_ranges, pages)?;
        }
    }
    Ok(())
}

fn parse_arm64(
    context: &ArmContext,
    memory: &mut dyn MemoryView,
    pa: u64,
) -> Result<Vec<ArmPageRange>, Error> {
    let ranges = context
        .granularity
        .get_level_ranges(context.virtual_address_space_size);
    let root = TablePointerEntry {
        va: !(((context.top_bit as u64) << context.virtual_address_space_size) - 1u64),
        base_address: pa,
        xn: false,
        pxn: false,
        permission_bits: 0,
        level: 0,
    };
    let mut page_entries = Vec::new();

    parse_block_arm64(&context, memory, &root, &ranges, &mut page_entries)?;

    Ok(page_entries)
}

pub fn collect_pages(
    context: &ArmContext,
    memory: &mut dyn MemoryView,
    pa: u64,
) -> Result<Vec<ArmPageRange>, Error> {
    match context.flavour {
        ArmFlavour::Arm64 => {
            return parse_arm64(&context, memory, pa);
        }
        ArmFlavour::Arm32 => {
            unreachable!();
        }
    }
}
