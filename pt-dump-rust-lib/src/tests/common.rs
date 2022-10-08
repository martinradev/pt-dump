use crate::memory::memory::MemoryView;
use crate::pt::common::Error;

pub struct MemoryViewFromArray {
    pub data: Vec<u8>,
}

impl MemoryViewFromArray {
    pub fn from(data: &[u8]) -> Self {
        Self {
            data: Vec::from(data),
        }
    }
}

impl MemoryView for MemoryViewFromArray {
    fn read_block(&mut self, offset: usize, block_size: usize) -> Result<Vec<u8>, Error> {
        if offset + block_size > self.data.len() {
            Err(Error::FailedToReadBlock)
        } else {
            Ok(Vec::from(&self.data[offset..offset + block_size]))
        }
    }

    fn read_block_inplace(
        &mut self,
        offset: usize,
        block_size: usize,
        block: &mut [u8],
    ) -> Result<(), Error> {
        if offset + block_size > self.data.len() {
            Err(Error::FailedToReadBlock)
        } else {
            block[..block_size].copy_from_slice(&self.data[offset..offset + block_size]);
            Ok(())
        }
    }
}
