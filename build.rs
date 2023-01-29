extern crate bindgen;

use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{DeriveInfo, ParseCallbacks};
use libbpf_cargo::{Error, SkeletonBuilder};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

const RUBY_STACK_SOURCE: &str = "./src/bpf/rbperf.bpf.c";
const RUBY_STACK_HEADER: &str = "./src/bpf/rbperf.h";
const RUBY_STACK_SKELETON: &str = "./src/bpf/rbperf.rs";

const FEATURES_SOURCE: &str = "./src/bpf/features.bpf.c";
const FEATURES_SKELETON: &str = "./src/bpf/features.rs";

#[derive(Debug)]
struct BuildCallbacks;

impl ParseCallbacks for BuildCallbacks {
    fn add_derives(&self, derive_info: &DeriveInfo) -> Vec<String> {
        if derive_info.name == "RubyVersionOffsets" {
            vec!["Serialize".into(), "Deserialize".into()]
        } else if derive_info.name == "RubyStack" {
            vec!["PartialEq".into(), "Eq".into()]
        } else {
            vec![]
        }
    }

    // Copied from bindgen::CargoCallbacks, to tell cargo to invalidate
    // the built crate whenever any of the included header files changed.
    fn include_file(&self, filename: &str) {
        println!("cargo:rerun-if-changed={filename}");
    }
}

fn main() {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(RUBY_STACK_HEADER)
        .parse_callbacks(Box::new(BuildCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_file = out_path.join("bindings.rs");
    bindings
        .write_to_file(&bindings_out_file)
        .expect("Couldn't write bindings!");

    // Add Serde includes
    let mut contents = String::new();
    File::open(&bindings_out_file)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    let new_contents = format!("use serde::{{Serialize, Deserialize}};\n{contents}");
    File::create(&bindings_out_file)
        .unwrap()
        .write_all(new_contents.as_bytes())
        .unwrap();

    let skel = Path::new(RUBY_STACK_SKELETON);
    match SkeletonBuilder::new()
        .source(RUBY_STACK_SOURCE)
        .clang_args("-Wextra -Wall -Werror")
        .build_and_generate(skel)
    {
        Ok(_) => {}
        Err(err) => match err {
            Error::Build(msg) | Error::Generate(msg) => {
                panic!("Error running SkeletonBuilder for rbperf = {msg}");
            }
        },
    }

    // Turn off some clippy warnings in the generated BPF skeleton.
    let mut contents = String::new();
    File::open(skel)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    let new_contents = format!("#![allow(clippy::derive_partial_eq_without_eq)]\n{contents}");
    File::create(skel)
        .unwrap()
        .write_all(new_contents.as_bytes())
        .unwrap();

    // BPF feature detection.
    let skel = Path::new(FEATURES_SKELETON);
    match SkeletonBuilder::new()
        .source(FEATURES_SOURCE)
        .clang_args("-Wextra -Wall -Werror")
        .build_and_generate(skel)
    {
        Ok(_) => {}
        Err(err) => match err {
            Error::Build(msg) | Error::Generate(msg) => {
                panic!("Error running SkeletonBuilder for feature detector = {msg}");
            }
        },
    }

    println!("cargo:rerun-if-changed={RUBY_STACK_SOURCE}");
    println!("cargo:rerun-if-changed={RUBY_STACK_HEADER}");
    println!("cargo:rerun-if-changed={FEATURES_SOURCE}");
}
