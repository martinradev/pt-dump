use crate::memory::memory::MemoryView;
use crate::pt::common::Error;

pub struct MemoryViewFd {
    fd: i32,
    gva_base: usize,
}

impl MemoryViewFd {
    pub fn new(fd: i32, gva_base: usize) -> Self {
        MemoryViewFd {
            fd: fd,
            gva_base: gva_base,
        }
    }
}

impl MemoryView for MemoryViewFd {
    fn read_block(&mut self, offset: usize, block_size: usize) -> Result<Vec<u8>, Error> {
        read_block_from_fd(self.fd, self.gva_base + offset, block_size)
    }

    fn read_block_inplace(&mut self, offset: usize, block_size: usize, block: &mut [u8]) -> Result<(), Error> {
        read_inline_block_from_fd(self.fd, self.gva_base + offset, block_size, block)
    }
}

pub fn read_block_from_fd(fd: i32, offset: usize, block_size: usize) -> Result<Vec<u8>, Error> {
    let mut block = vec![0u8; block_size];
    let result = unsafe {
        nc::pread64(
            fd,
            block.as_mut_ptr() as usize,
            block.len(),
            offset as nc::off_t,
        )
    };
    let return_value = match result {
        Ok(return_value) => {
            let return_value_usize = return_value as usize;
            if return_value_usize == block_size {
                Ok(block)
            } else {
                println!(
                    "Read block is smaller. Expected {:x}. Read: {:x}",
                    block_size, return_value_usize
                );
                Err(Error::FailedToReadBlock)
            }
        }
        Err(error_code) => {
            println!(
                "Failed to read block at offset {:x} with size 0x{:x}. fd: {}, Error code: {}",
                offset, block_size, fd, error_code
            );
            Err(Error::FailedToReadBlock)
        }
    };
    return_value
}

pub fn read_inline_block_from_fd(fd: i32, offset: usize, block_size: usize, block: &mut [u8]) -> Result<(), Error> {
    let result = unsafe {
        nc::pread64(
            fd,
            block.as_mut_ptr() as usize,
            block_size,
            offset as nc::off_t,
        )
    };
    let return_value = match result {
        Ok(return_value) => {
            let return_value_usize = return_value as usize;
            if return_value_usize == block_size {
                Ok(())
            } else {
                println!(
                    "Read block is smaller. Expected {:x}. Read: {:x}",
                    block_size, return_value_usize
                );
                Err(Error::FailedToReadBlock)
            }
        }
        Err(error_code) => {
            println!(
                "Failed to read block at offset {:x} with size 0x{:x}. fd: {}, Error code: {}",
                offset, block_size, fd, error_code
            );
            Err(Error::FailedToReadBlock)
        }
    };
    return_value
}