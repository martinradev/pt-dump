use byte_slice_cast::*;

use crate::{
    pt::common::PhysRange,
    pt::x86::PageAttributes,
    pt::x86::{self, X86Flavour, X86PageRange},
    tests::common::*,
};

pub fn compare_page_vectors(expected: &Vec<X86PageRange>, actual: &Vec<X86PageRange>) {
    assert_eq!(expected.len(), actual.len());
    for (a, b) in expected.iter().zip(actual.iter()) {
        if a != b {
            assert_eq!(a, b);
        }
    }
}

pub fn create_page(w: bool, u: bool, nx: bool, va: u64, phys: u64, extent: u64) -> X86PageRange {
    X86PageRange {
        attributes: PageAttributes {
            writeable: w,
            user: u,
            pwt: false,
            pcd: false,
            accessed: false,
            dirty: false,
            global: false,
            pat: false,
            nx: nx,
        },
        extent: extent,
        va: va,
        phys_ranges: vec![PhysRange::new(phys, extent)],
    }
}

// A single page
#[test]
fn test_pt_x86_single_page() {
    let mut mem = [0u32; 1024 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PDE
    mem[1024 * 1] = 0x2001; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, false, false).unwrap();
    assert_eq!(
        vec![create_page(false, false, false, 0, 0x2000, 0x1000)],
        result
    );
}

// Test multiple user pages
#[test]
fn test_pt_x86_multiple_pages() {
    let mut mem = [0u32; 1024 * 16]; // 16 physical pages
    mem[2] = 0x1001; // PDE
    mem[1024 * 1] = 0x2001; // PTE
    mem[1024 * 1 + 2] = 0x4001; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, false, false).unwrap();
    println!("{:?}", result);
    compare_page_vectors(
        &vec![
            create_page(false, false, false, 2 * 4 * 1024 * 1024, 0x2000, 0x1000),
            create_page(
                false,
                false,
                false,
                2 * 4 * 1024 * 1024 + 0x2000,
                0x4000,
                0x1000,
            ),
        ],
        &result,
    );
}

#[test]
fn test_pt_x86_pde_pdpe() {
    let mut mem = vec![0u32; 1024 * 1024 * 16];
    mem[0] = 0x1001; // PDE
    mem[8] = 0x800081; // PDE
    mem[1024] = 0x400001; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, true, false).unwrap();
    compare_page_vectors(
        &vec![
            create_page(false, false, false, 0, 4 * 1024 * 1024, 0x1000),
            create_page(
                false,
                false,
                false,
                8 * 4 * 1024 * 1024,
                8 * 1024 * 1024,
                4 * 1024 * 1024,
            ),
        ],
        &result,
    );
    let result = x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, false, false);
    match result {
        Err(e) => {
            println!("Got error: {:?}", e);
            assert!(false);
        }
        Ok(result) => {
            compare_page_vectors(
                &vec![create_page(false, false, false, 0, 4 * 1024 * 1024, 0x1000)],
                &result,
            );
        }
    }
}

// test all attributes
#[test]
fn test_pt_x86_all_attributes() {
    let mut mem = [0u32; 1024 * 16]; // 16 physical pages
    mem[0] = 0x2001; // PDE
    mem[1024 * 2] = 0x3001;
    mem[1024 * 2 + 2] = 0x4003;
    mem[1024 * 2 + 4] = 0x5005;
    mem[1024 * 2 + 6] = 0x6009;
    mem[1024 * 2 + 8] = 0x7011;
    mem[1024 * 2 + 10] = 0x8021;
    mem[1024 * 2 + 12] = 0x9041;
    mem[1024 * 2 + 14] = 0xa081;
    mem[1024 * 2 + 16] = 0xb101;
    mem[1024 * 2 + 18] = 0xc201;
    mem[1024 * 2 + 20] = 0xd401;
    mem[1024 * 2 + 22] = 0xe801;
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, false, false).unwrap();
    compare_page_vectors(
        &vec![
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 0,
                phys_ranges: vec![PhysRange::new(0x3000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: true,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 1,
                phys_ranges: vec![PhysRange::new(0x4000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: true,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 2,
                phys_ranges: vec![PhysRange::new(0x5000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: true,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 3,
                phys_ranges: vec![PhysRange::new(0x6000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: true,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 4,
                phys_ranges: vec![PhysRange::new(0x7000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: true,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 5,
                phys_ranges: vec![PhysRange::new(0x8000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: true,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 6,
                phys_ranges: vec![PhysRange::new(0x9000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 7,
                phys_ranges: vec![PhysRange::new(0xa000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: true,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 8,
                phys_ranges: vec![PhysRange::new(0xb000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 9,
                phys_ranges: vec![PhysRange::new(0xc000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 10,
                phys_ranges: vec![PhysRange::new(0xd000, 0x1000)],
            },
            X86PageRange {
                attributes: PageAttributes {
                    writeable: false,
                    user: false,
                    pwt: false,
                    pcd: false,
                    accessed: false,
                    dirty: false,
                    global: false,
                    pat: false,
                    nx: false,
                },
                extent: 0x1000,
                va: 0x2000 * 11,
                phys_ranges: vec![PhysRange::new(0xe000, 0x1000)],
            },
        ],
        &result,
    );
}

// pae
#[test]
fn test_pt_x86_pae() {
    let mut mem = [0u64; 512 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PDPE, 0 gig
    mem[2] = 0x8000000081; // +2 gig
    mem[512 * 1] = 0x081 + (2 * 1024 * 1024 * 1024); // PDE
    mem[512 * 1 + 1] = 0x2001; // + 2 MiB
    mem[512 * 2 + 1] = 0x600081; // PTE
    mem[512 * 2 + 3] = 0x800081; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result = x86::collect_pages(X86Flavour::X86, &mut memory_view, cr3, false, true).unwrap();
    compare_page_vectors(
        &vec![
            create_page(false, false, false, 0, 2 * 1024 * 1024 * 1024, 0x200000), // 2MiB
            create_page(false, false, false, 2 * 1024 * 1024 + 4096, 0x600000, 4096),
            create_page(
                false,
                false,
                false,
                2 * 1024 * 1024 + 3 * 4096,
                0x800000,
                4096,
            ),
            create_page(
                false,
                false,
                false,
                2 * 1024 * 1024 * 1024,
                0x8000000000,
                1024 * 1024 * 1024,
            ),
        ],
        &result,
    );
}

/*
 * Test XN bit with PAE
 */
#[test]
fn test_pt_x86_xn() {
    let mut mem = [0u64; 1024 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PDPE
    mem[3] = 0x4081 | (1u64 << 63); // PDPE
    mem[512 * 1] = 0x2001; // PDE
    mem[512 * 1 + 1] = (1024 * 1024 * 1024) | (1u64 << 63) | 0x81; // PDE
    mem[512 * 2] = 0x3001; // PTE
    mem[512 * 2 + 1] = 0x20081 | (1u64 << 63); // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, true, true).unwrap();
    assert_eq!(
        [false, true, true, true],
        [
            result[0].get_attributes().nx,
            result[1].get_attributes().nx,
            result[2].get_attributes().nx,
            result[3].get_attributes().nx
        ],
    );
}

#[test]
fn test_pt_x64_single_page() {
    let mut mem = [0u64; 1024 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PML4E
    mem[512 * 1] = 0x2001; // PDPE
    mem[512 * 2] = 0x3001; // PDE
    mem[512 * 3] = 0x4001; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X64, &mut memory_view, cr3, false, false).unwrap();
    assert_eq!(
        vec![create_page(false, false, false, 0, 0x4000, 0x1000)],
        result
    );
}

#[test]
fn test_pt_x64_xn() {
    let mut mem = [0u64; 1024 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PML4E
    mem[512 * 1] = 0x2001; // PDPE
    mem[512 * 1 + 1] = (1024 * 1024 * 1024) | (1u64 << 63) | 0x81; // PDPE
    mem[512 * 2] = 0x3001; // PDE
    mem[512 * 2 + 1] = 0x20081 | (1u64 << 63); // PDE
    mem[512 * 3] = 0x4001 | (1u64 << 63); // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X64, &mut memory_view, cr3, true, true).unwrap();
    assert_eq!(
        [true, true, true],
        [
            result[0].get_attributes().nx,
            result[1].get_attributes().nx,
            result[2].get_attributes().nx
        ],
    );
}

#[test]
fn test_pt_x64_pse() {
    // PAE and PSE must not matter when with x64
    for (pae, pse) in [(true, true), (false, true), (false, false)] {
        let mut mem = [0u64; 512 * 16]; // 16 physical pages
        mem[0] = 0x1001;
        mem[2] = 0x8000000081;
        mem[512 * 1] = 0x081 + (2 * 1024 * 1024 * 1024); // PDE
        mem[512 * 1 + 1] = 0x8001; // + 2 MiB
        let mem_as_u8 = mem.as_byte_slice();
        let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
        let cr3 = 0u64;
        let result = x86::collect_pages(X86Flavour::X64, &mut memory_view, cr3, pse, pae).unwrap();
        compare_page_vectors(
            &vec![
                create_page(
                    false,
                    false,
                    false,
                    0,
                    2 * 1024 * 1024 * 1024,
                    1024 * 1024 * 1024,
                ),
                create_page(
                    false,
                    false,
                    false,
                    2 * 512 * 1024 * 1024 * 1024,
                    0x8000000000,
                    512 * 1024 * 1024 * 1024,
                ),
            ],
            &result,
        );
    }
}

#[test]
fn test_pt_x64_invalid_pages() {
    let mut mem = [0u64; 1024 * 16]; // 16 physical pages
    mem[0] = 0x1001; // PML4E
    mem[1] = 0x9991001; // PML4E
    mem[512 * 1] = 0x2001; // PDPE
    mem[512 * 1 + 1] = 0x888882001; // PDPE
    mem[512 * 2] = 0x3001; // PDE
    mem[512 * 2 + 1] = 0xaaaaa3001; // PDE
    mem[512 * 3] = 0x4001; // PTE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X64, &mut memory_view, cr3, false, false).unwrap();
    assert_eq!(
        vec![create_page(false, false, false, 0, 0x4000, 0x1000)],
        result
    );
}

// add test for canonical addresses
#[test]
fn test_pt_x64_canonical_address() {
    let mut mem = [0u64; 1024 * 16]; // 16 physical pages
    mem[258] = 0x1001; // PML4E
    mem[512 * 1] = 0x2081; // PDPE
    let mem_as_u8 = mem.as_byte_slice();
    let mut memory_view = MemoryViewFromArray::from(&mem_as_u8);
    let cr3 = 0u64;
    let result =
        x86::collect_pages(x86::X86Flavour::X64, &mut memory_view, cr3, true, true).unwrap();
    assert_eq!(0xffff810000000_000, result[0].get_va());
}
