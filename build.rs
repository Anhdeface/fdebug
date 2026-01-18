// build.rs
#![allow(unused_imports)]

use std::env;

fn main() {
    // Prevent dead code elimination for integrity functions
    println!("cargo:rerun-if-changed=build.rs");
}