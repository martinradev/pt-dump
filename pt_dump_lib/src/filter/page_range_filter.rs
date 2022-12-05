use crate::pt::page_range::{GenericPage, GenericPageRange};
use crate::pt::x86::X86PageRange;
use crate::pt::arm::ArmPageRange;

pub struct PageRangeFilterX86 {
    writeable: Option<bool>,
    executable: Option<bool>,
    user_accessible: Option<bool>,
    superuser_accessible: Option<bool>,
    has_address: Option<u64>,
    va_range: Option<(Option<u64>, Option<u64>)>,
}

impl PageRangeFilterX86 {
    pub fn new() -> Self {
        Self {
            writeable: None,
            executable: None,
            user_accessible: None,
            superuser_accessible: None,
            has_address: None,
            va_range: None,
        }
    }

    pub fn set_writeable(&mut self, w: bool) {
        self.writeable = Some(w);
    }

    pub fn set_executable(&mut self, e: bool) {
        self.executable = Some(e);
    }

    pub fn set_user_accessible(&mut self, ua: bool) {
        self.user_accessible = Some(ua);
    }

    pub fn set_superuser_accessible(&mut self, sa: bool) {
        self.superuser_accessible = Some(sa);
    }

    pub fn set_has_address(&mut self, addr: u64) {
        self.has_address = Some(addr);
    }

    pub fn set_va_range(&mut self, start: Option<u64>, end: Option<u64>) {
        self.va_range = Some((start, end));
    }

    pub fn get_writeable(&self) -> Option<bool> {
        self.writeable
    }

    pub fn get_executable(&self) -> Option<bool> {
        self.executable
    }

    pub fn get_user_accessible(&self) -> Option<bool> {
        self.user_accessible
    }

    pub fn get_only_superuser_accessible(&self) -> Option<bool> {
        self.superuser_accessible
    }

    pub fn get_has_address(&self) -> Option<u64> {
        self.has_address
    }

    pub fn get_va_range(&self) -> Option<(Option<u64>, Option<u64>)> {
        self.va_range
    }
}

pub fn filter_x86_ranges(
    ranges: &Vec<X86PageRange>,
    filter: &PageRangeFilterX86,
) -> Vec<X86PageRange> {
    let mut filtered_ranges = vec![];
    let w_opt = filter.get_writeable();
    let x_opt = filter.get_executable();
    let u_opt = filter.get_user_accessible();
    let s_only_opt = filter.get_only_superuser_accessible();
    let has_addr_opt = filter.get_has_address();
    let va_range_opt = filter.get_va_range();
    let (va_begin, va_end) = if let Some(va_range) = va_range_opt {
        (va_range.0.unwrap_or(0_u64), va_range.1.unwrap_or(u64::MAX))
    } else {
        (0_u64, u64::MAX)
    };

    // TODO: find b,e indices using binary search, this can be abstracted.
    for range in ranges {
        let mut ok = true;
        ok &= va_begin < range.get_va();
        ok &= va_end > range.get_va();
        if let Some(has_addr) = has_addr_opt {
            ok &= has_addr >= range.get_va() && has_addr < range.get_va() + range.get_extent();
        }
        let attr = range.get_attributes();
        if let Some(w) = w_opt {
            ok &= w == attr.writeable;
        }
        if let Some(x) = x_opt {
            ok &= x == !attr.nx;
        }
        if let Some(u) = u_opt {
            ok &= u == attr.user;
        }
        if let Some(s_only) = s_only_opt {
            ok &= s_only == !attr.user;
        }
        if ok {
            filtered_ranges.push(range.clone());
        }
    }
    filtered_ranges
}

pub fn filter_aarch64_ranges(
    ranges: &Vec<ArmPageRange>,
    filter: &PageRangeFilterX86,
) -> Vec<ArmPageRange> {
    let mut filtered_ranges = vec![];
    let w_opt = filter.get_writeable();
    let x_opt = filter.get_executable();
    let u_opt = filter.get_user_accessible();
    let s_only_opt = filter.get_only_superuser_accessible();
    let has_addr_opt = filter.get_has_address();
    let va_range_opt = filter.get_va_range();
    let (va_begin, va_end) = if let Some(va_range) = va_range_opt {
        (va_range.0.unwrap_or(0_u64), va_range.1.unwrap_or(u64::MAX))
    } else {
        (0_u64, u64::MAX)
    };

    // TODO: find b,e indices using binary search, this can be abstracted.
    for range in ranges {
        let mut ok = true;
        ok &= va_begin < range.get_va();
        ok &= va_end > range.get_va();
        if let Some(has_addr) = has_addr_opt {
            ok &= has_addr >= range.get_va() && has_addr < range.get_va() + range.get_va_extent()
        }
        if let Some(w) = w_opt {
            ok &= (w == range.is_user_writeable()) || (w == range.is_kernel_writeable());
            if let Some(u) = u_opt {
                ok &= u == range.is_user_writeable();
            }
            if let Some(s) = s_only_opt {
                ok &= s == range.is_kernel_writeable();
            }
        } else {
            if let Some(u) = u_opt {
                ok &= (u == range.is_user_writeable()) || (u == range.is_user_readable()) || (u == range.is_user_executable());
            }
            if let Some(s) = s_only_opt {
                ok &= (s == range.is_kernel_writeable()) || (s == range.is_kernel_readable()) || (s == range.is_kernel_executable());
            }
        }
        if let Some(x) = x_opt {
            ok &= (x == range.is_user_executable()) || (x == range.is_kernel_executable());
            if let Some(u) = u_opt {
                ok &= u == range.is_user_executable();
            }
            if let Some(s) = s_only_opt {
                ok &= s == range.is_kernel_executable();
            }
        } else {
            if let Some(u) = u_opt {
                ok &= (u == range.is_user_writeable()) || (u == range.is_user_readable()) || (u == range.is_user_executable());
            }
            if let Some(s) = s_only_opt {
                ok &= (s == range.is_kernel_writeable()) || (s == range.is_kernel_readable()) || (s == range.is_kernel_executable());
            }
        }
        if ok {
            filtered_ranges.push(range.clone());
        }
    }
    filtered_ranges
}
