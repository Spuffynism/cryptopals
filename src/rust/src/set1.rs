extern crate rustc_serialize;

use self::rustc_serialize::{self, ToBase64};
use self::rustc_serialize::hex::FromHex;

pub fn challenge_1(s: &str) -> String {
	s.from_hex().unwrap().to_base64(base64::STANDARD);
	return s.to_string();
}