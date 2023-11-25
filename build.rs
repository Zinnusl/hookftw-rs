fn main() -> miette::Result<()> {
    let paths = [std::path::PathBuf::from("extern/hookFTW/library/src")];
    let mut b = autocxx_build::Builder::new("src/lib.rs", &paths).build();

    match b {
        Err(error) => {
            println!("{}", error);
        }
        Ok(mut b) => {
            b.cpp(true)
                .flag_if_supported("/MDd")
                .flag_if_supported("-D_DLL")
                .flag_if_supported("-xc++")
                .flag_if_supported("-fexceptions")
                .flag_if_supported("-ferror-limit=100")
                // .flag_if_supported("-fms-compatibility-version=19.10")
                // .flag_if_supported("-fms-compatibility")
                .compile("autocxx-non-trivial-type-on-stack-example");
            println!("cargo:rerun-if-changed=src/lib.rs");

            // let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
            // println!("cargo:rustc-link-search=native={}", manifest_dir.join("D:/Entwicklung/Cpp/Required_Stuff/lib").as_path().display());
            // println!("cargo:rustc-link-lib=dylib=dkcored-x64");
            // println!("cargo:rustc-link-lib=dylib=dkgeod-x64");
            // println!("cargo:rustc-link-lib=dylib=dkwind-x64");
        }
    };

    Ok(())
}

