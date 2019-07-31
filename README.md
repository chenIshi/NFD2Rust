# NFD-Rust
Simple cross compiler from domain specific language NFD to rust

[NFD](https://github.com/NetFuncDev/NFD-repo) is a cross platform domain specific language for network virtualization development, by default it will be compile to c++, and this simple cross compiler is to compile this NFD to Rust.

Originally trying to do it with LLVM will be my first thought, however, I am not pretty sure about the progress on Rust. So I simply use the Rust crate, [nom](https://github.com/Geal/nom), to build a small rust compiler.

## QuickStart Guide

1. Use `Rust Stable` instead of `Rust nightly`
2. Use 2015 version instead of 2018 version
