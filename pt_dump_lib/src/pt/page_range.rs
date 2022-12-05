use crate::pt::arm;
use crate::pt::common;
use crate::pt::x86;

pub trait GenericPage {
    fn get_va(&self) -> u64;
}

impl GenericPage for x86::X86PageRange {
    fn get_va(&self) -> u64 {
        return self.get_va();
    }
}

impl GenericPage for arm::ArmPageRange {
    fn get_va(&self) -> u64 {
        return self.va;
    }
}

/*
impl From<arm::ArmPage> for arm::ArmPage {
    fn from(page: arm::ArmPage) -> Self {
        page.clone()
    }
}
*/

pub trait GenericPageRange {
    fn get_phys_ranges(&self) -> &Vec<common::PhysRange>;
    fn get_va_start(&self) -> u64;
    fn get_va_extent(&self) -> u64;
}

impl GenericPageRange for x86::X86PageRange {
    fn get_phys_ranges(&self) -> &Vec<common::PhysRange> {
        self.get_phys_ranges()
    }

    fn get_va_start(&self) -> u64 {
        self.get_va()
    }

    fn get_va_extent(&self) -> u64 {
        self.get_extent()
    }
}

impl GenericPageRange for arm::ArmPageRange {
    fn get_phys_ranges(&self) -> &Vec<common::PhysRange> {
        &self.phys_ranges
    }

    fn get_va_start(&self) -> u64 {
        self.va
    }

    fn get_va_extent(&self) -> u64 {
        self.extent
    }
}
