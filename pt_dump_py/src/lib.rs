use std::sync::Arc;

use pt_dump_lib::filter::page_range_filter;
use pt_dump_lib::filter::page_range_filter::PageRangeFilterX86;
use pt_dump_lib::memory::memory::MemoryView;
use pt_dump_lib::print::printer::{Printer, X86Writer};
use pt_dump_lib::pt::arm;
use pt_dump_lib::pt::arm::ArmPageRange;
use pt_dump_lib::pt::page_range::*;
use pt_dump_lib::pt::x86::X86PageRange;
use pt_dump_lib::pt::*;
use pt_dump_lib::search::bytes_search::{self, SearchResult};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use qemu_memory::QemuMemoryView;
mod qemu_memory;

#[derive(FromPyObject)]
struct PyFilter_X86 {
    writeable: Option<bool>,
    executable: Option<bool>,
    user_accessible: Option<bool>,
    va_range: Option<(Option<u64>, Option<u64>)>,
    has_address: Option<u64>,
    only_superuser_accessible: Option<bool>,
}

trait PageTable<PageType> {
    fn get_ranges(&self) -> &Vec<PageType>;
    fn get_memory_view(&mut self) -> &mut QemuMemoryView;
}

#[pyclass]
pub struct PageTableX86 {
    ranges: Vec<X86PageRange>,
    memory_view: QemuMemoryView,
}

impl PageTableX86 {
    pub fn new(ranges: Vec<X86PageRange>, memory_view: QemuMemoryView) -> Self {
        PageTableX86 {
            ranges: ranges,
            memory_view: memory_view,
        }
    }
}

impl PageTable<X86PageRange> for PageTableX86 {
    fn get_ranges(&self) -> &Vec<X86PageRange> {
        &self.ranges
    }

    fn get_memory_view(&mut self) -> &mut QemuMemoryView {
        &mut self.memory_view
    }
}

#[pyclass]
pub struct PageTableAarch64 {
    ranges: Vec<ArmPageRange>,
    memory_view: QemuMemoryView,
}

impl PageTableAarch64 {
    pub fn new(ranges: Vec<ArmPageRange>, memory_view: QemuMemoryView) -> Self {
        PageTableAarch64 {
            ranges: ranges,
            memory_view: memory_view,
        }
    }
}

impl PageTable<ArmPageRange> for PageTableAarch64 {
    fn get_ranges(&self) -> &Vec<ArmPageRange> {
        &self.ranges
    }

    fn get_memory_view(&mut self) -> &mut QemuMemoryView {
        &mut self.memory_view
    }
}

#[pyfunction]
fn get_page_table_as_string(table: &PageTableX86) -> String {
    let mut writer = X86Writer::new();
    writer.write_ranges(&table.get_ranges());
    let result = writer.get_result();
    result.clone()
}

fn collect_ram_ranges(phys_ranges: &PyList) -> Result<Vec<qemu_memory::RamRange>, PyErr> {
    let mut phys_ranges_vec = vec![];
    for u in phys_ranges {
        let tuple = match u.downcast::<PyTuple>() {
            Err(e) => return Err(PyTypeError::new_err("todo")),
            Ok(tuple) => tuple,
        };
        if tuple.len() != 3 {
            return Err(PyTypeError::new_err("Expected a tuple"));
        }
        let gpa_start: usize = tuple.get_item(0).unwrap().extract().unwrap();
        let gpa_extent: usize = tuple.get_item(1).unwrap().extract().unwrap();
        let hva: usize = tuple.get_item(2).unwrap().extract().unwrap();
        phys_ranges_vec.push(qemu_memory::RamRange::new(gpa_start, gpa_extent, hva));
    }
    Ok(phys_ranges_vec)
}

fn create_memory_view(fd: i32, phys_ranges: &PyList) -> Result<QemuMemoryView, PyErr> {
    let ram_ranges = collect_ram_ranges(phys_ranges);
    let ram_ranges = match ram_ranges {
        Ok(ram_ranges_ok) => ram_ranges_ok,
        Err(err) => return Err(err),
    };
    let memory_view = match qemu_memory::QemuMemoryView::new(fd, &ram_ranges, true) {
        Err(err) => {
            return Err(pyo3::exceptions::PyIOError::new_err(
                "Couldn't open QEMU mem fd",
            ))
        }
        Ok(res) => res,
    };
    Ok(memory_view)
}

fn pages_to_ranges<PageType: GenericPage + Clone, RangeType: GenericPageRange + From<PageType>>(
    pages: &Vec<PageType>,
) -> Vec<RangeType> {
    pages.iter().map(|x| RangeType::from(x.clone())).collect()
}

#[pyfunction]
fn parse_page_table_x86_32(
    fd: i32,
    cr3: u64,
    pae: bool,
    pse: bool,
    phys_ranges: &PyList,
) -> PyResult<PageTableX86> {
    let mut memory_view = create_memory_view(fd, &phys_ranges)?;
    let pages = x86::collect_pages(x86::X86Flavour::X86, &mut memory_view, cr3, pse, pae);
    if let Ok(pages_ok) = pages {
        Ok(PageTableX86::new(pages_to_ranges(&pages_ok), memory_view))
    } else {
        return Err(PyTypeError::new_err("Failed to collect pages"));
    }
}

#[pyfunction]
fn parse_page_table_x86_64(
    fd: i32,
    cr3: u64,
    pae: bool,
    pse: bool,
    phys_ranges: &PyList,
) -> PyResult<PageTableX86> {
    let mut memory_view = create_memory_view(fd, &phys_ranges)?;
    let pages = x86::collect_pages(x86::X86Flavour::X64, &mut memory_view, cr3, pse, pae);
    if let Ok(pages_ok) = pages {
        Ok(PageTableX86::new(pages_to_ranges(&pages_ok), memory_view))
    } else {
        return Err(PyTypeError::new_err("Failed to collect pages"));
    }
}

#[pyfunction]
fn parse_page_table_aarch64(
    fd: i32,
    pt_pa: u64,
    phys_ranges: &PyList,
) -> PyResult<PageTableAarch64> {
    let mut memory_view = create_memory_view(fd, &phys_ranges)?;
    let arm_context = arm::ArmContext::new(arm::ArmFlavour::Arm64, arm::Granularity::Pt4k, 0, 0);
    let pages = arm::collect_pages(&arm_context, &mut memory_view, pt_pa);
    if let Ok(pages_ok) = pages {
        Ok(PageTableAarch64::new(
            pages_to_ranges(&pages_ok),
            memory_view,
        ))
    } else {
        return Err(PyTypeError::new_err("Failed to collect pages"));
    }
}

#[pyfunction]
fn filter_page_table_x86(table: &mut PageTableX86, filter: &PyAny) -> PyResult<PageTableX86> {
    let filter: PyFilter_X86 = filter.extract()?;
    let mut pt_filter = PageRangeFilterX86::new();
    if let Some(e) = filter.executable {
        pt_filter.set_executable(e);
    }
    if let Some(w) = filter.writeable {
        pt_filter.set_writeable(w);
    }
    if let Some(has_address) = filter.has_address {
        pt_filter.set_has_address(has_address);
    }
    if let Some(su) = filter.only_superuser_accessible {
        pt_filter.set_superuser_accessible(su);
    }
    if let Some(u) = filter.user_accessible {
        pt_filter.set_user_accessible(u);
    }
    if let Some(r) = filter.va_range {
        pt_filter.set_va_range(r.0, r.1);
    }

    let memory_view = table.get_memory_view().clone();
    Ok(PageTableX86::new(
        page_range_filter::filter_x86_ranges(table.get_ranges(), &pt_filter),
        memory_view,
    ))
}

fn search_memory_generic<
    PageRangeType: GenericPageRange + ToString,
    PageTableType: PageTable<PageRangeType>,
>(
    table: &mut PageTableType,
    data: &[u8],
    alignment: u64,
    max_found: usize,
) -> PyResult<String> {
    let mut memory_view = table.get_memory_view().clone();
    let ranges = table.get_ranges();
    let search_result = bytes_search::search_memory_generic(
        &data,
        ranges,
        &mut memory_view,
        Some(alignment),
        max_found,
    );
    let occs = search_result.get_results();
    if occs.is_empty() {
        return Ok(String::from("Not found"));
    }

    let mut saved_range = (occs[0].range_index, ranges[occs[0].range_index].to_string());
    let mut result_str = String::new();
    for occ in occs {
        if occ.range_index != saved_range.0 {
            saved_range = (occ.range_index, ranges[occ.range_index].to_string())
        }
        result_str.push_str(&format!(
            "Found at 0x{:016x} in {}\n",
            occ.va, saved_range.1
        ));
    }
    Ok(result_str)
}

#[pyfunction]
fn search_memory_x86(
    table: &mut PageTableX86,
    data_py: &PyBytes,
    alignment: u64,
    max_found: usize,
) -> PyResult<String> {
    search_memory_generic(table, data_py.as_bytes(), alignment, max_found)
}

#[pyfunction]
fn search_memory_aarch64(
    table: &mut PageTableAarch64,
    data_py: &PyBytes,
    alignment: u64,
    max_found: usize,
) -> PyResult<String> {
    search_memory_generic(table, data_py.as_bytes(), alignment, max_found)
}

#[pyclass]
struct KaslrInfo {
    #[pyo3(get)]
    image_virt: Option<u64>,

    #[pyo3(get)]
    image_phys: Option<u64>,

    #[pyo3(get)]
    physmap_virt: Option<u64>,
}

#[pyfunction]
fn find_kaslr_linux_x86(table: &mut PageTableX86) -> PyResult<KaslrInfo> {
    let mut kaslr_info = KaslrInfo {
        image_virt: None,
        image_phys: None,
        physmap_virt: None,
    };

    let mut filter_and_search = |is_executable: bool| -> Option<(u64, Option<u64>)> {
        let memory_view = table.get_memory_view().clone();
        let mut pt_filter = PageRangeFilterX86::new();
        pt_filter.set_executable(is_executable);
        pt_filter.set_superuser_accessible(true);
        let filtered_pt = PageTableX86::new(
            page_range_filter::filter_x86_ranges(table.get_ranges(), &pt_filter),
            memory_view,
        );

        // Next find 2-MiB-aligned pages which has the byte 0x48 at the beginning.
        let alignment = 2 * 1024 * 1024;
        let linux_base_needle = [0x48_u8];

        let mut memory_view = table.get_memory_view().clone();
        let ranges = filtered_pt.get_ranges();
        let search_result = bytes_search::search_memory_generic(
            &linux_base_needle,
            ranges,
            &mut memory_view,
            Some(alignment),
            1,
        );
        let occ = search_result.get_results();
        if occ.is_empty() {
            None
        } else {
            Some((
                occ[0].va,
                filtered_pt.get_ranges()[occ[0].range_index].gva_to_gpa(occ[0].va),
            ))
        }
    };

    let image_info = filter_and_search(true);
    if let Some(image_info_ok) = image_info {
        kaslr_info.image_virt = Some(image_info_ok.0);
        kaslr_info.image_phys = image_info_ok.1;
    }

    let physbase_info = filter_and_search(false);
    if let Some(physbase_info_ok) = physbase_info {
        kaslr_info.physmap_virt = Some(physbase_info_ok.0);
    }

    Ok(kaslr_info)
}

#[pymodule]
fn gdb_pt_dump_rust_py_interface(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_page_table_x86_32, m)?)?;
    m.add_function(wrap_pyfunction!(parse_page_table_x86_64, m)?)?;
    m.add_function(wrap_pyfunction!(parse_page_table_aarch64, m)?)?;
    // TODO: riscv64
    m.add_function(wrap_pyfunction!(get_page_table_as_string, m)?)?;

    m.add_function(wrap_pyfunction!(filter_page_table_x86, m)?)?;
    // TODO: aarch64
    // TODO: riscv64

    m.add_function(wrap_pyfunction!(search_memory_x86, m)?)?;
    m.add_function(wrap_pyfunction!(search_memory_aarch64, m)?)?;
    // TODO: riscv64

    m.add_function(wrap_pyfunction!(find_kaslr_linux_x86, m)?)?;
    // TODO: aarch64
    // TODO: riscv64

    Ok(())
}
