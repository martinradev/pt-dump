#[cfg(test)]
mod tests {
    use {crate::memory::memory::MemoryView, rand::*};

    fn gen_random_data(data_size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0usize..data_size)
            .into_iter()
            .map(|_| {
                let b: u8 = rng.gen();
                b
            })
            .collect();
        data
    }

    fn generate_fd_from_slice(data: &[u8]) -> i32 {
        let file_result = unsafe { nc::open(".", nc::O_TMPFILE | nc::O_RDWR, 0666) };
        assert_eq!(true, file_result.is_ok());
        let fd = file_result.unwrap();
        let result = unsafe { nc::write(fd, data.as_ptr() as usize, data.len()) }.unwrap();
        assert_eq!(true, result >= 0);
        assert_eq!(result as usize, data.len());
        return fd;
    }

    #[test]
    fn test_memory_view_fd() {
        let data_size = 32 * 1024;
        let data = gen_random_data(data_size);
        let fd = generate_fd_from_slice(&data[..]);
        let mut memory_view = crate::memory::memory_fd::MemoryViewFd::new(fd, 0);
        assert_eq!(data[0], memory_view.read_block(0, 1).unwrap()[0]);
        assert_eq!(data[1], memory_view.read_block(1, 1).unwrap()[0]);
        assert_eq!(
            data[data_size - 1],
            memory_view.read_block(data_size - 1, 1).unwrap()[0]
        );
        assert_eq!(
            data[data_size / 2..],
            memory_view
                .read_block(data_size / 2, data_size / 2)
                .unwrap()
        );
    }
}
