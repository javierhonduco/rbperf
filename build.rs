extern crate bindgen;

use std::env;
use std::path::PathBuf;

use std::path::Path;

use libbpf_cargo::{Error, SkeletonBuilder};

const SRC: &str = "./src/bpf/rbperf.bpf.c";

fn main() {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/bpf/rbperf.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let skel = Path::new("./src/bpf/mod.rs");
    match SkeletonBuilder::new(SRC).generate(&skel) {
        Ok(_) => {}
        Err(err) => match err {
            Error::Build(msg) => {
                panic!("Error running SkeletonBuilder = {}", msg);
            }
            Error::Generate(msg) => {
                panic!("Error running SkeletonBuilder = {}", msg);
            }
        },
    }
    println!("cargo:rerun-if-changed={}", SRC);
}
