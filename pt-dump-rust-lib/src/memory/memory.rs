use crate::pt::common::Error;

pub trait MemoryView: Send + Sync {
    fn read_block(&mut self, offset: usize, block_size: usize) -> Result<Vec<u8>, Error>;
    fn read_block_inplace(
        &mut self,
        offset: usize,
        block_size: usize,
        block: &mut [u8],
    ) -> Result<(), Error>;
}
