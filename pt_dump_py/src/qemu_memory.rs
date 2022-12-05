use lru::LruCache;
use nc;
use pt_dump_lib::{memory::memory::MemoryView, memory::memory_fd::*, pt::common::Error};
use std::num::NonZeroUsize;

#[derive(Copy, Clone, Debug)]
pub struct RamRange {
    gpa_start: usize,
    gpa_extent: usize,
    hva: usize,
}

impl RamRange {
    pub fn new(gpa_start: usize, gpa_extent: usize, hva: usize) -> Self {
        Self {
            gpa_start: gpa_start,
            gpa_extent: gpa_extent,
            hva: hva,
        }
    }
}

pub struct QemuMemoryView {
    sorted_ram_ranges: Vec<RamRange>,
    mem_fd: i32,
    use_cache: bool,
    cache: LruCache<(usize, usize), Vec<u8>>,
}

impl QemuMemoryView {
    pub fn new(
        mem_fd: i32,
        sorted_ram_ranges: &Vec<RamRange>,
        use_cache: bool,
    ) -> Result<Self, Error> {
        let new_owned_fd = match unsafe { nc::dup(mem_fd) } {
            Ok(new_fd) => new_fd,
            Err(_) => return Err(Error::ResourceError),
        };
        Ok(Self {
            mem_fd: new_owned_fd,
            sorted_ram_ranges: sorted_ram_ranges.clone(),
            use_cache: use_cache,
            cache: LruCache::new(NonZeroUsize::new(2048).unwrap()),
        })
    }

    pub fn find_phys_ranges(
        &self,
        gpa_start: usize,
        gpa_end_excl: usize,
    ) -> Option<(usize, usize)> {
        if gpa_start >= gpa_end_excl {
            return None;
        }
        let mut start_result = None;
        let mut end_result = None;
        for i in 0..self.sorted_ram_ranges.len() {
            let ram_range = &self.sorted_ram_ranges[i];
            if start_result.is_none()
                && ((ram_range.gpa_start <= gpa_start
                    && ram_range.gpa_start + ram_range.gpa_extent > gpa_start)
                    || (ram_range.gpa_start >= gpa_start))
            {
                start_result = Some(i);
            }
            if ram_range.gpa_start < gpa_end_excl {
                end_result = Some(i);
            }
        }
        if let (Some(start), Some(end)) = (start_result, end_result) {
            if start_result <= end_result {
                Some((start, end))
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Drop for QemuMemoryView {
    fn drop(&mut self) {
        let ret_value = unsafe { nc::close(self.mem_fd) };
        if let Err(err) = ret_value {
            println!("Failed to close qemu mem_fd. Error: {}", err);
        }
    }
}

impl Clone for QemuMemoryView {
    fn clone(&self) -> Self {
        let mut tmp = Self {
            sorted_ram_ranges: self.sorted_ram_ranges.clone(),
            mem_fd: unsafe { nc::dup(self.mem_fd).unwrap() },
            use_cache: self.use_cache,
            cache: LruCache::new(NonZeroUsize::new(2048).unwrap()),
        };

        for (key, value) in self.cache.iter() {
            tmp.cache.put(*key, value.clone());
        }

        tmp
    }
}

impl MemoryView for QemuMemoryView {
    fn read_block(&mut self, gpa: usize, block_size: usize) -> Result<Vec<u8>, Error> {
        if self.use_cache {
            let value = self.cache.get(&(gpa, block_size));
            if let Some(value_ok) = value {
                return Ok(value_ok.clone());
            }
        }
        let mut block = vec![0u8; block_size];
        let result = self.read_block_inplace(gpa, block_size, &mut block[..]);
        if let Err(e) = result {
            Err(e)
        } else {
            Ok(block)
        }
    }

    fn read_block_inplace(
        &mut self,
        gpa: usize,
        block_size: usize,
        block: &mut [u8],
    ) -> Result<(), Error> {
        if self.use_cache {
            let value = self.cache.get(&(gpa, block_size));
            if let Some(value_ok) = value {
                block.copy_from_slice(&value_ok[0..block_size]);
                return Ok(());
            }
        }

        let ranges = self.find_phys_ranges(gpa, gpa + block_size);
        if let Some((start_index, end_index)) = ranges {
            for index in start_index..=end_index {
                let range = &self.sorted_ram_ranges[index];
                let gpa_start = std::cmp::max(gpa, range.gpa_start);
                let gpa_offset = gpa_start - range.gpa_start;
                let max_to_read = std::cmp::min(
                    range.gpa_extent - gpa_offset,
                    block_size - (gpa_start - gpa),
                );
                let va_start = range.hva + gpa_offset;
                let cur_pos = gpa_start - gpa;

                // Ignore error.
                let _ = read_inline_block_from_fd(
                    self.mem_fd,
                    va_start,
                    max_to_read,
                    &mut block[cur_pos..],
                );
            }
            self.cache.put((gpa, block_size), Vec::from(block));
            Ok(())
        } else {
            Err(Error::FailedToReadBlock)
        }
    }
}

#[test]
fn test_qemu_memory_view() {
    let pid = unsafe { nc::getpid() };
    assert_eq!(true, pid > 0);
    let sorted_ranges = vec![
        RamRange::new(0x2000, 0x1000, 0x2000),
        RamRange::new(0x4000, 0x1000, 0x4000),
        RamRange::new(0x8000, 0x1000, 0x8000),
        RamRange::new(0xa000, 0x10000, 0xa000),
        RamRange::new(0x11a000, 0x100000, 0x11a000),
    ];
    let qemu_memory_path = format!("/proc/{}/mem", pid);
    let mem_fd = unsafe { nc::open(qemu_memory_path, nc::O_RDONLY, 0) }.unwrap();
    let mut qemuMem = QemuMemoryView::new(mem_fd, &sorted_ranges).unwrap();
    let range = qemuMem.find_phys_ranges(0x3000, 0x9000);
    assert_eq!(Some((1, 2)), range);

    let range = qemuMem.find_phys_ranges(0x2000, 0x2000);
    assert_eq!(None, range);

    let range = qemuMem.find_phys_ranges(0x2000, 0x2001);
    assert_eq!(Some((0, 0)), range);

    let range = qemuMem.find_phys_ranges(0x2fff, 0x3000);
    assert_eq!(Some((0, 0)), range);

    let range = qemuMem.find_phys_ranges(0x2fff, 0x2fff);
    assert_eq!(None, range);

    let range = qemuMem.find_phys_ranges(0x2000, 0x4000);
    assert_eq!(Some((0, 0)), range);

    let range = qemuMem.find_phys_ranges(0x2000, 0x4001);
    assert_eq!(Some((0, 1)), range);

    let range = qemuMem.find_phys_ranges(0x11a000, 0x20000000);
    assert_eq!(
        Some((sorted_ranges.len() - 1, sorted_ranges.len() - 1)),
        range
    );
}

#[test]
fn test_memory_read() {
    let pid = unsafe { nc::getpid() };
    assert_eq!(true, pid > 0);
    let sz = 0x10000;
    let base_va = unsafe {
        nc::mmap(
            0,
            sz,
            nc::PROT_READ | nc::PROT_WRITE,
            nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .unwrap();
    let base_va_u8 = unsafe { std::slice::from_raw_parts_mut(base_va as *mut u8, sz) };
    for page_index in 0..(sz / 0x1000) {
        let off = page_index * 0x1000;
        base_va_u8[off..off + 0x1000].fill((page_index + 1) as u8);
    }

    let sorted_ranges = vec![
        RamRange::new(0x0, 0x3000, base_va),
        RamRange::new(0x4000, 0x4000, base_va + 0x4000),
        RamRange::new(0x8000, 0x1000, base_va + 0x8000),
        RamRange::new(0xa000, 0x2000, base_va + 0xa000),
    ];

    let qemu_memory_path = format!("/proc/{}/mem", pid);
    let mem_fd = unsafe { nc::open(qemu_memory_path, nc::O_RDONLY, 0) }.unwrap();
    let mut qemuMem = QemuMemoryView::new(mem_fd, &sorted_ranges).unwrap();
    assert_eq!(vec![1u8; 0x1000], qemuMem.read_block(0x0, 0x1000).unwrap());
    assert_eq!(
        vec![2u8; 0x1000],
        qemuMem.read_block(0x1000, 0x1000).unwrap()
    );
    assert_eq!(
        vec![3u8; 0x1000],
        qemuMem.read_block(0x2000, 0x1000).unwrap()
    );
    assert_eq!(true, qemuMem.read_block(0x3000, 0x1000).is_err());
    let tmp = [
        vec![5u8; 0x1000],
        vec![6u8; 0x1000],
        vec![7u8; 0x1000],
        vec![8u8; 0x1000],
        vec![9u8; 0x1000],
    ]
    .concat();
    assert_eq!(tmp, qemuMem.read_block(0x4000, 0x5000).unwrap());
    assert_eq!(tmp, qemuMem.read_block(0x4000, 0x5000).unwrap());
    assert_eq!(vec![0xb; 0x10], qemuMem.read_block(0xa000, 0x10).unwrap());
    let mut tmp = vec![0u8; sz];
    for range in sorted_ranges {
        for rel_offset in (0..range.gpa_extent).step_by(0x1000) {
            let offset = range.gpa_start + rel_offset;
            tmp[offset..offset + 0x1000].fill(((offset / 0x1000) + 1) as u8);
        }
    }
    assert_eq!(tmp, qemuMem.read_block(0, sz).unwrap());
    assert_eq!(
        [vec![0x8; 0x8], vec![0x9; 0x8]].concat(),
        qemuMem.read_block(0x7ff8, 0x10).unwrap()
    );
}
