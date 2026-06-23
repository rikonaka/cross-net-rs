pub mod error;
pub mod iface;
pub mod neigh;
pub mod route;

pub type Result<T, E = error::CrossNetError> = std::result::Result<T, E>;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
