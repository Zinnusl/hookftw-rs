# hookFTW - hook for the win(dows)
[![Rust](https://github.com/Zinnusl/hookftw-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/Zinnusl/hookftw-rs/actions/workflows/rust.yml)
A hooking library for Windows (32/64 Bit) with Linux support.

Rust rewrite with improved usage.

## Usage
1. Add to cargo

```
cargo add --git https://github.com/Zinnusl/hookftw-rs.git
```

2. Use hookftw-rs

```rust
use hookftw-rs::{Detour};

let detour = Detour::hook(target_address, fn_to_execute);

// later if desired
detour.unhook();
```
