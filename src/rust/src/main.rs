extern crate rustc_serialize;
extern crate core;

mod set1;

fn main() {
	let numerator:f64 = 330_323.0;
	let denominator:f64 = 152_680.0 * (152_680.0 - 1.0);
	
	println!("{}", (numerator / denominator).to_string());
}