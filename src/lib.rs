use autocxx::prelude::*;

include_cpp! {
    // C++ headers we want to include.
    #include "Detour.h"
    #include "Detour.cpp"
    safety!(unsafe)
    // A non-trivial C++ type
    generate!("Detour")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // Put the non-trivial C++ type on the Rust stack.
        moveit! { let mut detour = ffi::Detour::new(); }
        // // Call methods on it.

        // moveit! { let mut radian = ffi::DkGeo::Radian::new(); }
        println!("epsilon: {}", 1.0);
    }
}
