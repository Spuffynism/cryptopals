// Converts a string to a vector of its bytes
#[macro_export]
macro_rules! vs {
( $ x: expr) => ( $ x.as_bytes().to_vec());
}