use std::collections::VecDeque;

use crate::pt::common::{Error, PhysRange};
use crate::memory::memory::MemoryView;

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
    tcr: u64,
    virtual_address_space_size: u8,
}

impl ArmContext {
    pub fn new(
        flavour: ArmFlavour,
        granularity: Granularity,
        tcr: u64,
        virtual_address_space_size: u8,
    ) -> Self {
        Self {
            flavour: flavour,
            granularity: granularity,
            tcr: tcr,
            virtual_address_space_size: virtual_address_space_size,
        }
    }
}

#[derive(Clone)]
pub struct ArmPageRange {
    pub va: u64,
    pub extent: u64,
    pub phys_ranges: Vec<PhysRange>,
    pub xn: bool,
    pub pxn: bool,
    pub permission_bits: u8,
}

#[derive(Copy, Clone)]
struct LevelRangeInfo {
    bit_start_incl: u8,
    bit_end_incl: u8,
    block_size: u64,
}

#[derive(Copy, Clone)]
struct LevelRanges {
    level0: Option<LevelRangeInfo>, // This is None for 64K granularity
    level1: LevelRangeInfo,
    level2: LevelRangeInfo,
    level3: LevelRangeInfo,
}

impl LevelRanges {
    fn get_level_info(self: &Self, index: u8) -> LevelRangeInfo {
        match index {
            0 => {
                if let Some(level0) = self.level0 {
                    return level0;
                } else {
                    unreachable!();
                }
            }
            1 => self.level1,
            2 => self.level2,
            3 => self.level3,
            _ => unreachable!(),
        }
    }
}

impl Granularity {
    fn get_block_size(self) -> usize {
        match self {
            Granularity::Pt4k => 0x1000,
            Granularity::Pt16k => 0x10000,
            Granularity::Pt64k => 0x40000,
        }
    }

    fn get_level_ranges(self) -> LevelRanges {
        match self {
            Granularity::Pt4k => LevelRanges {
                level0: Some(LevelRangeInfo {
                    bit_start_incl: 39,
                    bit_end_incl: 47,
                    block_size: 512_u64 * 1024 * 1024 * 1024,
                }),
                level1: LevelRangeInfo {
                    bit_start_incl: 30,
                    bit_end_incl: 38,
                    block_size: 1024_u64 * 1024 * 1024,
                },
                level2: LevelRangeInfo {
                    bit_start_incl: 21,
                    bit_end_incl: 29,
                    block_size: 2_u64 * 1024 * 1024,
                },
                level3: LevelRangeInfo {
                    bit_start_incl: 12,
                    bit_end_incl: 20,
                    block_size: 4096,
                },
            },
            Granularity::Pt16k => LevelRanges {
                level0: Some(LevelRangeInfo {
                    bit_start_incl: 47,
                    bit_end_incl: 47,
                    block_size: 128_u64 * 1024 * 1024 * 1024 * 1024,
                }),
                level1: LevelRangeInfo {
                    bit_start_incl: 36,
                    bit_end_incl: 46,
                    block_size: 64_u64 * 1024 * 1024 * 1024,
                },
                level2: LevelRangeInfo {
                    bit_start_incl: 25,
                    bit_end_incl: 35,
                    block_size: 32_u64 * 1024 * 1024,
                },
                level3: LevelRangeInfo {
                    bit_start_incl: 14,
                    bit_end_incl: 24,
                    block_size: 16 * 1024,
                },
            },
            Granularity::Pt64k => LevelRanges {
                level0: None,
                level1: LevelRangeInfo {
                    bit_start_incl: 42,
                    bit_end_incl: 51,
                    block_size: 4_u64 * 1024 * 1024 * 1024 * 1024,
                },
                level2: LevelRangeInfo {
                    bit_start_incl: 29,
                    bit_end_incl: 41,
                    block_size: 512 * 1024 * 1024,
                },
                level3: LevelRangeInfo {
                    bit_start_incl: 16,
                    bit_end_incl: 28,
                    block_size: 64 * 1024,
                },
            },
        }
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

struct MappingPointerEntry {
    va: u64,
    extent: u64,
    base_address: u64,
    xn: bool,
    pxn: bool,
    permission_bits: u8,
}

fn parse_block_arm64(
    context: &ArmContext,
    memory: &mut dyn MemoryView,
    table: &TablePointerEntry,
    level_ranges: &LevelRanges,
    mut tables: &mut VecDeque<TablePointerEntry>,
    mut pages: &mut Vec<MappingPointerEntry>,
) -> Result<(), Error> {
    let level_info = level_ranges.get_level_info(table.level);
    let block_size = context.granularity.get_block_size();
    let block = memory.read_block(table.base_address as usize, block_size)?;

    let mask_range = |(a_inclusive, b_inclusive): (u8, u8)| {
        let mask_to_zero = |a_inclusive: u8| (1_u64 << a_inclusive) - 1_u64;
        mask_to_zero(a_inclusive) ^ mask_to_zero(b_inclusive)
    };

    let extract_bits = |value: u64, a_inclusive: u8, b_inclusive: u8| {
        value & (mask_range((a_inclusive, b_inclusive)) >> a_inclusive)
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
        let base_address = extract_bits_no_shift(
            raw_entry,
            level_ranges.level3.bit_start_incl,
            level_ranges.level3.bit_end_incl,
        );

        // TODO: do we have to propagate permission bit from the parent table? Most likely yes
        if (table_pointer && contiguous_bit) || !table_pointer {
            // this is a leaf page
            let permissions = ((raw_entry >> 6) & 0x2) as u8;
            let xn = has_bit(54) || table.xn;
            let pxn = has_bit(53) || table.pxn;
            let entry = MappingPointerEntry {
                va: va,
                base_address: base_address,
                xn: xn,
                pxn: pxn,
                permission_bits: permissions,
                extent: level_info.block_size,
            };
            pages.push(entry);
        } else {
            // this is table
            let permissions = ((raw_entry >> 61) & 0x2) as u8;
            let xn = has_bit(60) | table.xn;
            let pxn = has_bit(59) | table.pxn;
            TablePointerEntry {
                va: va,
                base_address: base_address,
                xn: xn,
                pxn: pxn,
                permission_bits: permissions,
                level: table.level + 1,
            };
        }
    }
    Ok(())
}

fn parse_arm64(
    context: &ArmContext,
    memory: &mut dyn MemoryView,
    pa: u64,
) -> Result<Vec<ArmPageRange>, Error> {
    let ranges = context.granularity.get_level_ranges();
    let root = TablePointerEntry {
        va: 0,
        base_address: pa,
        xn: false,
        pxn: false,
        permission_bits: 0,
        level: 0,
    };
    let mut page_entries = Vec::new();
    let mut tables = VecDeque::new();
    tables.push_back(root);

    while !tables.is_empty() {
        if let Some(head) = tables.pop_front() {
            parse_block_arm64(
                &context,
                memory,
                &head,
                &ranges,
                &mut tables,
                &mut page_entries,
            )?;
        } else {
            // There should also be an entry unless code is somehow broken.
            unreachable!();
        }
    }

    let mut arm_page_entries = Vec::with_capacity(page_entries.len());
    for mapping_entry in &page_entries {
        arm_page_entries.push(ArmPageRange {
            va: mapping_entry.va,
            extent: mapping_entry.extent,
            phys_ranges: vec![PhysRange::new(mapping_entry.base_address, mapping_entry.extent)],
            xn: mapping_entry.xn,
            pxn: mapping_entry.pxn,
            permission_bits: mapping_entry.permission_bits,
        });
    }

    Ok(arm_page_entries)
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
