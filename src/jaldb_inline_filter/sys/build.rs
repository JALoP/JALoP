use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let jalop_root = {
        // JALOP_ROOT is set in scons during a full jalop build
        // or, for a local cargo build the relative root is up three
        let top = env::var("JALOP_ROOT").or(env::var("CARGO_MANIFEST_DIR").map(|sys| format!("{sys}/../../..")))?;
        fs::canonicalize(PathBuf::from(top)).map(|p| p.display().to_string())?
    };

    // the profile env is set by cargo
    let profile = match env::var("PROFILE") {
        Ok(p) if p == "release" => p,
        _ => "debug".to_owned(),
    };

    // link path for the current profile
    let libs_path = format!("{jalop_root}/{profile}/lib");

    println!("cargo:rustc-link-search=native={libs_path}");
    println!("cargo:rustc-link-lib=jal-common");
    println!("cargo:rustc-link-lib=jal-db");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    // binding generation is only supported on rhel 9
    #[cfg(feature = "rhel9")]
    {
        use anyhow::Context;
        use bindgen;

        let includes: Vec<_> = ["lmdb_layer", "network_stores", "lib_common"]
            .iter()
            .map(|s| format!("-I{jalop_root}/src/{s}/src"))
            .collect();

        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .allowlist_function("jaldb_context_create")
            .allowlist_function("jaldb_context_destroy")
            .allowlist_function("jaldb_context_init")
            .allowlist_function("jaldb_mark_unsynced_records_unsent")
            .allowlist_function("jaldb_mark_sent")
            .allowlist_function("jaldb_mark_synced")
            .allowlist_function("jaldb_next_unsynced_record")
            .allowlist_function("jaldb_next_chronological_record")
            .allowlist_function("jaldb_get_record")
            .allowlist_function("jaldb_destroy_record")
            .allowlist_function("get_jaldb_config")
            .allowlist_function("free_jaldb_config")
            .allowlist_function("jal_gen_timestamp_usec")
            .allowlist_type("mark_request")
            .allowlist_type("jaldb_segment")
            .clang_args(includes)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .context("failed to gen bindings")?;

        bindings.write_to_file("src/bindings.rs").context("failed to write bindings")?;
    }
    Ok(())
}
