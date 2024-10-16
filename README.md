![hookftw banner](img/hookftw_banner.png)
![example workflow](https://github.com/fahersto/hookFTW/actions/workflows/cmake.yml/badge.svg)
# hookFTW - hook for the win(dows)
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
