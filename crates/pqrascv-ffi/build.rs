fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = std::path::PathBuf::from(&crate_dir).join("../../include");
    std::fs::create_dir_all(&output_dir).unwrap();

    let config =
        cbindgen::Config::from_file(std::path::Path::new(&crate_dir).join("cbindgen.toml"))
            .unwrap_or_default();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(output_dir.join("pqrascv.h"));
        }
        Err(e) => {
            println!("cargo:warning=cbindgen failed, skipping header generation: {e}");
        }
    }
}
