use crate::memory::memory;
use crate::pt::common::{Error, PhysRange};

struct X86Context {
    flavour: X86Flavour,
    pml4e_range: Option<(u8, u8)>, // This is not valid for x86-32
    pdpe_range: Option<(u8, u8)>,  // Valid for x86-32 only if PAE is used. For x86-32-pae, 30:31
    pde_range: (u8, u8),           // 21:29 (PAE) or 22:31
    pte_range: (u8, u8),           // 12:20 (PAE) or 12:21
    page_size: usize,
    entry_size: usize,
    pse: bool, // set to true if in PAE mode or if flavour is x86_64
    pae: bool,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum LevelType {
    PML4,
    PDP,
    PD,
    PT,
}

fn get_next_level_type(lvl: LevelType) -> LevelType {
    match lvl {
        LevelType::PML4 => LevelType::PDP,
        LevelType::PDP => LevelType::PD,
        LevelType::PD => LevelType::PT,
        LevelType::PT => unreachable!(),
    }
}

fn level_type_to_index(lvl: LevelType) -> usize {
    match lvl {
        LevelType::PML4 => 0,
        LevelType::PDP => 1,
        LevelType::PD => 2,
        LevelType::PT => 3,
    }
}

#[derive(Copy, Clone, Debug)]
struct TablePointerEntry {
    table_address: u64, // bit 12
    level: LevelType,
    va: u64,
    remaining_bits: u8,
}

#[derive(Clone, PartialEq, Debug)]
pub struct PageAttributes {
    pub accessed: bool,
    pub dirty: bool,
    pub writeable: bool,
    pub user: bool,
    pub pwt: bool,
    pub pcd: bool,
    pub pat: bool,
    pub global: bool,
    pub nx: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub struct X86PageRange {
    pub va: u64,
    pub extent: u64,
    pub attributes: PageAttributes,
    pub phys_ranges: Vec<PhysRange>,
}

impl X86PageRange {
    pub fn new(va: u64, extent: u64, attr: PageAttributes, ranges: Vec<PhysRange>) -> Self {
        Self {
            va: va,
            extent: extent,
            attributes: attr,
            phys_ranges: ranges,
        }
    }

    pub fn get_va(&self) -> u64 {
        self.va
    }

    pub fn get_extent(&self) -> u64 {
        self.extent
    }

    pub fn get_attributes(&self) -> &PageAttributes {
        &self.attributes
    }

    pub fn get_phys_ranges(&self) -> &Vec<PhysRange> {
        &self.phys_ranges
    }

    fn is_extendable_by(&self, next_va: u64, next_attributes: &PageAttributes) -> bool {
        (self.va + self.extent) == next_va
            && self.attributes.writeable == next_attributes.writeable
            && self.attributes.user == next_attributes.user
            && self.attributes.nx == next_attributes.nx
    }

    fn extend_by(&mut self, next_extent: u64, next_phys: u64) {
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

enum TableEntry {
    X86PageRange(X86PageRange),
    TablePointerEntry(TablePointerEntry),
}

fn parse_entry<'h>(
    x86_context: &X86Context,
    current_level: LevelType,
    raw_entry: u64,
    va_contribution: u64,
    remaining_bits: u8,
    block_size: u64,
    previous_page: &'h mut Option<&mut X86PageRange>,
) -> Result<Option<TableEntry>, Error> {
    let has_bit = |bit_loc: u8| ((raw_entry >> bit_loc) & 1_u64) == 1_u64;
    let present = has_bit(0);
    if !present {
        return Ok(None);
    }

    let writeable = has_bit(1);
    let user = has_bit(2);
    let pwt = has_bit(3);
    let pcd = has_bit(4);
    let accessed = has_bit(5);
    let dirty = has_bit(6);
    let ps = if x86_context.pse { has_bit(7) } else { false };
    let global = has_bit(8);
    let pat = if current_level == LevelType::PT {
        false
    } else {
        has_bit(12)
    };
    let nx = has_bit(63); // there is no nx bit when the table entry is 4-bytes-long

    let mask_range = |(a_inclusive, b_inclusive): (u8, u8)| {
        let mask_to_zero = |a_inclusive: u8| (1_u64 << a_inclusive) - 1_u64;
        mask_to_zero(a_inclusive) ^ mask_to_zero(b_inclusive)
    };
    let end_entry = ps || (current_level == LevelType::PT);
    let address_mask = if end_entry {
        match current_level {
            LevelType::PML4 => mask_range((x86_context.pml4e_range.unwrap().0, 51)),
            LevelType::PDP => mask_range((x86_context.pdpe_range.unwrap().0, 51)),
            LevelType::PD => mask_range((x86_context.pde_range.0, 51)),
            LevelType::PT => mask_range((x86_context.pte_range.0, 51)),
        }
    } else {
        let zero_to_fifty = (1_u64 << 51) - 1_u64;
        let zero_to_eleven = (1_u64 << 12) - 1_u64;
        zero_to_fifty ^ zero_to_eleven
    };
    let address = raw_entry & address_mask;

    let result: TableEntry = if end_entry {
        let top_address_bit = (va_contribution >> 47) & 1;
        let canonical_va = if top_address_bit != 0 {
            let canonical_va_mask = 0xFFFF000000000000_u64;
            va_contribution | canonical_va_mask
        } else {
            va_contribution
        };

        let attr = PageAttributes {
            accessed: accessed,
            dirty: dirty,
            writeable: writeable,
            user: user,
            pwt: pwt,
            pcd: pcd,
            pat: pat,
            global: global,
            nx: nx,
        };

        if let Some(previous_page) = previous_page {
            if previous_page.is_extendable_by(canonical_va, &attr) {
                previous_page.extend_by(block_size, address);
                return Ok(None);
            }
        }
        TableEntry::X86PageRange(X86PageRange::new(
            canonical_va,
            block_size,
            attr,
            vec![PhysRange::new(address, block_size)],
        ))
    } else {
        TableEntry::TablePointerEntry(TablePointerEntry {
            table_address: address,
            va: va_contribution,
            remaining_bits: remaining_bits,
            level: get_next_level_type(current_level),
        })
    };
    Ok(Some(result))
}

fn collect_entries_recursive<'a>(
    memory: &mut dyn memory::MemoryView,
    x86_context: &X86Context,
    current_page_table: &TablePointerEntry,
    mut scratch_memory: &mut Vec<Vec<u8>>,
    block_size: usize,
    pages: &mut Vec<X86PageRange>,
) {
    let bits_contribution = match (
        x86_context.flavour,
        current_page_table.level,
        x86_context.entry_size,
    ) {
        (_, _, 4) => 10,
        (X86Flavour::X86, LevelType::PDP, 8) => 2,
        (_, _, 8) => 9,
        _ => unreachable!(),
    };
    let current_block = scratch_memory[level_type_to_index(current_page_table.level)].as_ptr();

    for index in 0..block_size / x86_context.entry_size {
        let raw_entry: u64 = match x86_context.entry_size {
            4 => {
                (unsafe { *(current_block.add(index * x86_context.entry_size) as *const u32) })
                    as u64
            }
            8 => unsafe { *(current_block.add(index * x86_context.entry_size) as *const u64) },
            _ => unreachable!(),
        };
        let present = (raw_entry & 0x1) == 0x1;
        if !present {
            // Early optimization for not present
            continue;
        }
        let remaining_bits = current_page_table.remaining_bits - bits_contribution;
        let va_contribution = (index as u64) << remaining_bits;
        let block_size = 1_u64 << remaining_bits;
        let entry = parse_entry(
            &x86_context,
            current_page_table.level,
            raw_entry,
            current_page_table.va | va_contribution,
            remaining_bits,
            block_size,
            &mut pages.last_mut(),
        )
        .unwrap();
        match entry {
            Some(TableEntry::TablePointerEntry(table)) => {
                // Intentionally ignore errors
                let index = level_type_to_index(table.level);
                let result = memory.read_block_inplace(
                    table.table_address as usize,
                    x86_context.page_size,
                    &mut scratch_memory[index][..],
                );
                if result.is_ok() {
                    collect_entries_recursive(
                        memory,
                        x86_context,
                        &table,
                        &mut scratch_memory,
                        x86_context.page_size,
                        pages,
                    );
                }
            }
            Some(TableEntry::X86PageRange(mapping)) => {
                pages.push(mapping);
            }
            None => continue,
        }
    }
}

fn collect_pages_common(
    memory: &mut dyn memory::MemoryView,
    flavour: X86Flavour,
    root: &TablePointerEntry,
    x86_context: &X86Context,
    mut pages: &mut Vec<X86PageRange>,
) -> Result<(), Error> {
    // The algorithm perform DFS, and thus at most Five blocks are used at any point.
    let mut scratch_memory = vec![vec![0u8; x86_context.page_size]; 5];
    if flavour == X86Flavour::X86 && x86_context.pae {
        memory.read_block_inplace(
            root.table_address as usize,
            4 * 8,
            &mut scratch_memory[level_type_to_index(root.level)][..],
        )?;
        collect_entries_recursive(
            memory,
            &x86_context,
            root,
            &mut scratch_memory,
            4 * 8,
            &mut pages,
        );
    } else {
        memory.read_block_inplace(
            root.table_address as usize,
            x86_context.page_size,
            &mut scratch_memory[level_type_to_index(root.level)][..],
        )?;
        collect_entries_recursive(
            memory,
            &x86_context,
            root,
            &mut scratch_memory,
            x86_context.page_size,
            &mut pages,
        );
    }
    Ok(())
}

#[derive(PartialEq, Clone, Copy)]
pub enum X86Flavour {
    X86,
    X64,
}

struct LevelRanges {
    pml4e_range: Option<(u8, u8)>,
    pdpe_range: Option<(u8, u8)>,
    pde_range: (u8, u8),
    pte_range: (u8, u8),
}

fn gen_level_ranges(flavour: X86Flavour, pae: bool) -> LevelRanges {
    if flavour == X86Flavour::X86 {
        if pae {
            LevelRanges {
                pml4e_range: None,
                pdpe_range: Some((30, 31)),
                pde_range: (21, 29),
                pte_range: (12, 20),
            }
        } else {
            LevelRanges {
                pml4e_range: None,
                pdpe_range: None,
                pde_range: (22, 31),
                pte_range: (12, 21),
            }
        }
    } else if flavour == X86Flavour::X64 {
        LevelRanges {
            pml4e_range: Some((39, 47)),
            pdpe_range: Some((30, 38)),
            pde_range: (21, 29),
            pte_range: (12, 20),
        }
    } else {
        unreachable!()
    }
}

pub fn collect_pages(
    flavour: X86Flavour,
    memory: &mut dyn memory::MemoryView,
    pa: u64,
    pse: bool,
    pae: bool,
) -> Result<Vec<X86PageRange>, Error> {
    // Construct the x86 context for parsing
    let (num_entries, entry_size) = if flavour == X86Flavour::X86 {
        if pae {
            (512usize, 8usize)
        } else {
            (1024usize, 4usize)
        }
    } else if flavour == X86Flavour::X64 {
        (512usize, 8usize)
    } else {
        unreachable!();
    };
    let ranges = gen_level_ranges(flavour, pae);
    let x86_context = X86Context {
        flavour: flavour,
        pml4e_range: ranges.pml4e_range,
        pdpe_range: ranges.pdpe_range,
        pde_range: ranges.pde_range,
        pte_range: ranges.pte_range,
        page_size: num_entries * entry_size,
        entry_size: entry_size,
        pse: if flavour == X86Flavour::X64 || pae {
            true
        } else {
            pse
        },
        pae: pae,
    };

    let mut pages = Vec::new();
    let root = TablePointerEntry {
        table_address: pa,
        level: if flavour == X86Flavour::X64 {
            LevelType::PML4
        } else if flavour == X86Flavour::X86 && pae {
            LevelType::PDP
        } else {
            LevelType::PD
        },
        remaining_bits: if flavour == X86Flavour::X64 { 48 } else { 32 },
        va: 0,
    };
    collect_pages_common(memory, flavour, &root, &x86_context, &mut pages)?;
    Ok(pages)
}
