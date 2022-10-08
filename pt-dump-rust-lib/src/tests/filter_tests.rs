use crate::filter::page_range_filter::{filter_x86_ranges, PageRangeFilterX86};
use crate::pt::common::PhysRange;
use crate::pt::x86::{PageAttributes, X86PageRange};

#[cfg(test)]
#[test]
fn test_x86_filter_each_attribute() {
    let ranges = vec![
        X86PageRange::new(
            0x10000,
            0x10000,
            PageAttributes {
                accessed: false,
                dirty: false,
                writeable: false,
                user: false,
                pwt: false,
                pcd: false,
                pat: false,
                global: false,
                nx: true,
            },
            Vec::<PhysRange>::new(),
        ),
        X86PageRange::new(
            0x30000,
            0x10000,
            PageAttributes {
                accessed: false,
                dirty: false,
                writeable: true,
                user: false,
                pwt: false,
                pcd: false,
                pat: false,
                global: false,
                nx: false,
            },
            Vec::<PhysRange>::new(),
        ),
        X86PageRange::new(
            0x90000,
            0x10000,
            PageAttributes {
                accessed: false,
                dirty: false,
                writeable: false,
                user: true,
                pwt: false,
                pcd: false,
                pat: false,
                global: false,
                nx: false,
            },
            Vec::<PhysRange>::new(),
        ),
        X86PageRange::new(
            0xb0000,
            0x10000,
            PageAttributes {
                accessed: false,
                dirty: false,
                writeable: true,
                user: true,
                pwt: false,
                pcd: false,
                pat: false,
                global: false,
                nx: true,
            },
            Vec::<PhysRange>::new(),
        ),
    ];

    let mut filter = PageRangeFilterX86::new();
    filter.set_writeable(true);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[1].clone(), ranges[3].clone()], filtered_ranges);
    filter.set_writeable(false);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[0].clone(), ranges[2].clone()], filtered_ranges);

    let mut filter = PageRangeFilterX86::new();
    filter.set_executable(true);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[1].clone(), ranges[2].clone()], filtered_ranges);
    filter.set_executable(false);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[0].clone(), ranges[3].clone()], filtered_ranges);

    let mut filter = PageRangeFilterX86::new();
    filter.set_user_accessible(true);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[2].clone(), ranges[3].clone()], filtered_ranges);
    filter.set_user_accessible(false);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[0].clone(), ranges[1].clone()], filtered_ranges);

    let mut filter = PageRangeFilterX86::new();
    filter.set_writeable(true);
    filter.set_executable(false);
    filter.set_user_accessible(true);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[3].clone()], filtered_ranges);

    let mut filter = PageRangeFilterX86::new();
    filter.set_writeable(false);
    filter.set_executable(false);
    filter.set_superuser_accessible(true);
    let filtered_ranges = filter_x86_ranges(&ranges, &filter);
    assert_eq!(vec![ranges[0].clone()], filtered_ranges);
}

#[test]
fn test_x86_filter_has_address() {
    let attr = PageAttributes {
        accessed: false,
        dirty: false,
        writeable: false,
        user: false,
        pwt: false,
        pcd: false,
        pat: false,
        global: false,
        nx: true,
    };
    let ranges = vec![
        X86PageRange::new(0x10000, 0x10000, attr.clone(), Vec::<PhysRange>::new()),
        X86PageRange::new(0x20000, 0x1000, attr.clone(), Vec::<PhysRange>::new()),
        X86PageRange::new(0x21000, 0xa0000, attr.clone(), Vec::<PhysRange>::new()),
        X86PageRange::new(0xaaa0000, 0x2000, attr.clone(), Vec::<PhysRange>::new()),
    ];

    // Check different ranges
    let tests = [
        (0x1000, ranges.len()),
        (0x10000, 0),
        (0x1ffff, 0),
        (0x20000, 1),
        (0x20500, 1),
        (0x20fff, 1),
        (0xaaa0000, 3),
        (0xaaa1fff, 3),
        (0xaaa2000, ranges.len()),
    ];
    let mut filter = PageRangeFilterX86::new();
    for (addr, index) in tests {
        filter.set_has_address(addr);
        let filtered_ranges = filter_x86_ranges(&ranges, &filter);

        if index == ranges.len() {
            assert_eq!(Vec::<X86PageRange>::new(), filtered_ranges);
        } else {
            assert_eq!(vec![ranges[index].clone()], filtered_ranges);
        }
    }
}
