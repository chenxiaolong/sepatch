#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]
// We use a very tiny fraction of these types.
#![allow(unused)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
