use crate::pt::arm::ArmPageRange;
use crate::pt::page_range::{GenericPage, GenericPageRange};
use crate::pt::x86::X86PageRange;
use colored::*;

fn select_color(w: bool, x: bool, r: bool) -> Color {
    if x && w {
        Color::Blue
    } else if x {
        Color::Red
    } else if w {
        Color::Green
    } else if r {
        Color::TrueColor {
            r: 0x80,
            g: 0x80,
            b: 0x80,
        }
    } else {
        Color::Black
    }
}

pub trait Printer<T> {
    fn write_ranges(&mut self, ranges: &Vec<T>);
}

pub struct X86Writer {
    pub address_column_length: u8,
    pub length_column_length: u8,
    pub permissions_column_length: u8,
    clear_color: String,
    result: String,
}

impl ToString for X86PageRange {
    fn to_string(&self) -> String {
        let attr = self.get_attributes();
        let color = select_color(attr.writeable, !attr.nx, true);
        let s = format!(
            "{va:>#21x} : {len:>#14x} : W:{w} X:{x} U:{u}",
            va = self.get_va(),
            len = self.get_extent(),
            w = attr.writeable as u8,
            x = !attr.nx as u8,
            u = attr.user as u8
        );
        format!(
            "{}{}",
            &s.on_color(color).to_string(),
            " ".on_black().to_string()
        )
    }
}

impl X86Writer {
    pub fn new() -> Self {
        let mut tmp = Self {
            address_column_length: 18,
            length_column_length: 12,
            permissions_column_length: 18,
            clear_color: " ".on_black().to_string(),
            result: String::new(),
        };
        let mut header = format!(
            "{:<20}   {:<14}   {}\n",
            "Virtual Address", "Length", "Permissions"
        );
        header.push_str(String::from("-").repeat(60).as_str());
        header += "\n";
        tmp.result += &header;
        tmp
    }

    pub fn get_result(&self) -> &String {
        &self.result
    }

    fn write_single_range(&mut self, range: &X86PageRange) {
        self.result.push_str(&range.to_string());
        self.result += "\n";
    }
}

impl Printer<X86PageRange> for X86Writer {
    fn write_ranges(&mut self, ranges: &Vec<X86PageRange>) {
        for range in ranges {
            self.write_single_range(&range);
        }
    }
}

pub struct Aarch64Writer {
    pub address_column_length: u8,
    pub length_column_length: u8,
    pub permissions_column_length: u8,
    clear_color: String,
    result: String,
}

impl Aarch64Writer {
    pub fn new() -> Self {
        let mut tmp = Self {
            address_column_length: 18,
            length_column_length: 12,
            permissions_column_length: 18,
            clear_color: " ".on_black().to_string(),
            result: String::new(),
        };
        let mut header = format!(
            "{:>21}   {:>14}  {:>16} {:>17}\n",
            "Virtual Address", "Length", "User space", "Kernel space"
        );
        header.push_str(String::from("-").repeat(74).as_str());
        header += "\n";
        tmp.result += &header;
        tmp
    }

    pub fn get_result(&self) -> &String {
        &self.result
    }

    fn write_single_range(&mut self, range: &ArmPageRange) {
        self.result.push_str(&range.to_string());
        self.result += "\n";
    }
}

impl Printer<ArmPageRange> for Aarch64Writer {
    fn write_ranges(&mut self, ranges: &Vec<ArmPageRange>) {
        for range in ranges {
            self.write_single_range(&range);
        }
    }
}

impl ToString for ArmPageRange {
    fn to_string(&self) -> String {
        let ur = self.is_user_readable();
        let uw = self.is_user_writeable();
        let ux = self.is_user_executable();
        let kr = self.is_kernel_readable();
        let kw = self.is_kernel_writeable();
        let kx = self.is_kernel_executable();
        let ucolor = select_color(uw, ux, ur);
        let kcolor = select_color(kw, kx, kr);
        let addr = format!(
            "{va:>#21x} : {len:>#14x}",
            va = self.get_va(),
            len = self.get_va_extent(),
        );
        let ur = ur as u8;
        let uw = uw as u8;
        let ux = ux as u8;
        let kr = kr as u8;
        let kw = kw as u8;
        let kx = kx as u8;
        let uinfo = format!("   R:{ur} W:{uw} X:{ux}   ");
        let kinfo = format!("   R:{kr} W:{kw} X:{kx}   ");
        format!(
            "{}|{}|{}{}",
            &addr.on_black().to_string(),
            &uinfo.on_color(ucolor).to_string(),
            &kinfo.on_color(kcolor).to_string(),
            " ".on_black().to_string()
        )
    }
}
