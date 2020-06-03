use ::aes::{Iv, Key};

pub mod ctr;
pub mod cbc;
pub mod ecb;

pub struct CipherWithIvAndKey<'a> {
    pub cipher: Vec<u8>,
    pub iv: &'a Iv,
    pub key: &'a Key,
}
