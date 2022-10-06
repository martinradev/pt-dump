use crate::pt::page_range::GenericPageRange;
use crate::memory::memory::MemoryView;
use memchr::memmem;

pub struct SearchResultOccurrence {
    pub va: u64,
    pub range_index: usize,
}

pub struct SearchResult {
    occurrences: Vec<SearchResultOccurrence>
}

impl SearchResult {
    fn new() -> Self {
        Self {
            occurrences: vec![]
        }
    }

    fn add_result(&mut self, range_index: usize, va_addr: u64) {
        self.occurrences.push(SearchResultOccurrence {
            va: va_addr,
            range_index: range_index
        })
    }

    pub fn get_results(&self) -> &Vec<SearchResultOccurrence> {
        &self.occurrences
    }
}

pub fn search_memory_generic<RangeType: GenericPageRange>(needle: &[u8], ranges: &Vec<RangeType>, memory_view: &mut dyn MemoryView, max_num_occurrences: usize) -> SearchResult {
    let mut result = SearchResult::new();
    let mut num_found = 0;
    for (range_index, range) in ranges.iter().enumerate() {
        let mut va_off = 0;
        for phys_range in range.get_phys_ranges().iter() {
            let block = memory_view.read_block(phys_range.phys_base as usize, phys_range.phys_extent as usize);
            if let Ok(block_ok) = block {
                let it = memmem::find_iter(&block_ok[..], &needle);
                for found_offset in it {
                    let va_addr = range.get_va_start() + (found_offset as u64) + va_off;
                    result.add_result(range_index, va_addr);
                    num_found += 1;
                    if num_found >= max_num_occurrences {
                        break;
                    }
                }
            }
            va_off += phys_range.phys_extent;
        }
        if num_found >= max_num_occurrences {
            break;
        }
    }
    result
}