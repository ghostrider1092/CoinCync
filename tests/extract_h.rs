#[test]
fn print_h_generator() {
    let h = coincync::crypto::generator_h();
    let bytes = h.compress().to_bytes();
    print!("H_BYTES: [");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("0x{:02x}", b);
    }
    println!("]");
}
