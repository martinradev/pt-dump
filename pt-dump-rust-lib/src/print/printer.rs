use crate::pt::arm::ArmPageRange;
use crate::pt::x86::X86PageRange;
use colored::*;

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
        let color = match (!attr.nx, attr.writeable) {
            (true, true) => Color::Blue,
            (false, true) => Color::Green,
            (true, false) => Color::Red,
            _ => Color::Black,
        };
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

impl ToString for ArmPageRange {
    fn to_string(&self) -> String {
        unimplemented!()
    }
}
