#[derive(Clone, PartialEq, Debug)]
pub struct PhysRange {
    pub phys_base: u64,
    pub phys_extent: u64,
}

impl PhysRange {
    pub fn new(base: u64, extent: u64) -> Self {
        Self {
            phys_base: base,
            phys_extent: extent,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    FailedToReadBlock,

    GenericParsingError,

    PML4ParsingError,
    PDPParsingError,
    PDParsingError,
    PTParsingError,

    PML4ReadingError,
    PDPReadingError,
    PDReadingError,
    PTReadingError,

    InvalidBlock,
    FailedToOpenFile,

    ResourceError,
}
