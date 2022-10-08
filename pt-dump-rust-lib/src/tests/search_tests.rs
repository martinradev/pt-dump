use crate::filter::page_range_filter::{filter_x86_ranges, PageRangeFilterX86};
use crate::pt::common::PhysRange;
use crate::pt::x86::{PageAttributes, X86PageRange};
use crate::tests::common::*;

use byte_slice_cast::*;

#[test]
fn search_for_bytes_identity_mapping() {
    use crate::search::bytes_search::search_memory_generic;

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

    let mut mem = vec![0u8; 1024];
    let ranges = vec![X86PageRange::new(
        0,
        mem.len() as u64,
        attr.clone(),
        vec![PhysRange::new(0, mem.len() as u64)],
    )];

    let needle = "KeyWord".as_byte_slice();
    let mut copy_needle_to = |off| mem[off..off + needle.len()].copy_from_slice(&needle);
    copy_needle_to(0);
    copy_needle_to(10);
    copy_needle_to(1024 - needle.len());
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 100);
    assert_eq!(
        vec![0, 10, 1024 - needle.len() as u64],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );
    assert_eq!(
        vec![0, 0, 0],
        result
            .get_results()
            .iter()
            .map(|x| x.range_index)
            .collect::<Vec<usize>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 3);
    assert_eq!(
        vec![0, 10, 1024 - needle.len() as u64],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 2);
    assert_eq!(
        vec![0, 10],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 1);
    assert_eq!(
        vec![0],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 0);
    assert_eq!(
        Vec::<u64>::new(),
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let needle = "KeyWor".as_byte_slice();
    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 100);
    assert_eq!(
        vec![0, 10, 1023 - needle.len() as u64],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );
    assert_eq!(
        vec![0, 0, 0],
        result
            .get_results()
            .iter()
            .map(|x| x.range_index)
            .collect::<Vec<usize>>()
    );

    let needle = "KeyWord!".as_byte_slice();
    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 100);
    assert_eq!(
        Vec::<u64>::new(),
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );
    assert_eq!(
        Vec::<usize>::new(),
        result
            .get_results()
            .iter()
            .map(|x| x.range_index)
            .collect::<Vec<usize>>()
    );
}

#[test]
fn search_for_bytes_identity_non_identity() {
    use crate::search::bytes_search::search_memory_generic;

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

    let mut mem = vec![0u8; 0x20000];
    let ranges = vec![
        X86PageRange::new(
            0xa00000,
            0x2000,
            attr.clone(),
            vec![
                PhysRange::new(0x1000, 0x1000),
                PhysRange::new(0x3000, 0x1000),
            ],
        ),
        X86PageRange::new(
            0xb00000,
            0x1000,
            attr.clone(),
            vec![PhysRange::new(0x9000, 0x1000)],
        ),
    ];

    let needle = "KeyWord".as_byte_slice();
    let mut copy_needle_to = |off| mem[off..off + needle.len()].copy_from_slice(&needle);
    copy_needle_to(0x1000);
    copy_needle_to(0x1f00);
    copy_needle_to(0x3500);
    copy_needle_to(0x9400);
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 100);
    assert_eq!(
        vec![0xa00000, 0xa00f00, 0xa01500, 0xb00400],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );
    assert_eq!(
        vec![0, 0, 0, 1],
        result
            .get_results()
            .iter()
            .map(|x| x.range_index)
            .collect::<Vec<usize>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 3);
    assert_eq!(
        vec![0xa00000, 0xa00f00, 0xa01500],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 2);
    assert_eq!(
        vec![0xa00000, 0xa00f00],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );

    let result = search_memory_generic(&needle, &ranges, &mut memory_view, 1);
    assert_eq!(
        vec![0xa00000],
        result
            .get_results()
            .iter()
            .map(|x| x.va)
            .collect::<Vec<u64>>()
    );
}
