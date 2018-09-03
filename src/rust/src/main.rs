
fn main() {
	let numerateur:f64 = 330_323.0;
	let denominateur:f64 = 152_680.0 * (152_680.0 - 1.0);
	
	println!("{}", (numerateur / denominateur).to_string());
}