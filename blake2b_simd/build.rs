// With the `bend` feature, compile libbendblake2b from ../c (or $BEND_BLAKE2B_C_DIR):
// bendblake2b.c is the C that Bend 2.0.34 generates from c/entry.bend (see c/build.sh).
fn main() {
    println!("cargo:rerun-if-env-changed=BEND_BLAKE2B_C_DIR");
    #[cfg(feature = "bend")]
    {
        use std::path::PathBuf;
        let dir = std::env::var_os("BEND_BLAKE2B_C_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../c"));
        for f in ["bendblake2b.c", "blake2b_ffi.c", "bend_blake2b.h"] {
            println!("cargo:rerun-if-changed={}", dir.join(f).display());
        }
        let mut b = cc::Build::new();
        if std::env::var_os("CC").is_none() {
            b.compiler("clang"); // Bend's generated C wants clang 14+
        }
        b.file(dir.join("bendblake2b.c"))
            .include(&dir)
            .std("c11")
            .opt_level(3)
            .define("main", "bendblake2b_unused_main")
            .flag("-fvisibility=hidden")
            .warnings(false)
            .compile("bendblake2b");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }
}
