// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: LGPL-2.1-or-later

use std::{env, path::PathBuf};

/// This intentionally tries to mirror Android.bp as closely as possible.
fn build_libsepol() {
    cc::Build::new()
        .file("external/selinux/libsepol/src/assertion.c")
        .file("external/selinux/libsepol/src/avrule_block.c")
        // .file("external/selinux/libsepol/src/avtab.c")
        .file("external/selinux_hackery/src/avtab_wrapper.c")
        .file("external/selinux/libsepol/src/boolean_record.c")
        .file("external/selinux/libsepol/src/booleans.c")
        .file("external/selinux/libsepol/src/conditional.c")
        .file("external/selinux/libsepol/src/constraint.c")
        .file("external/selinux/libsepol/src/context.c")
        .file("external/selinux/libsepol/src/context_record.c")
        .file("external/selinux/libsepol/src/debug.c")
        // .file("external/selinux/libsepol/src/ebitmap.c")
        .file("external/selinux_hackery/src/ebitmap_wrapper.c")
        .file("external/selinux/libsepol/src/expand.c")
        .file("external/selinux/libsepol/src/handle.c")
        .file("external/selinux/libsepol/src/hashtab.c")
        .file("external/selinux/libsepol/src/hierarchy.c")
        .file("external/selinux/libsepol/src/iface_record.c")
        .file("external/selinux/libsepol/src/interfaces.c")
        .file("external/selinux/libsepol/src/kernel_to_cil.c")
        .file("external/selinux/libsepol/src/kernel_to_common.c")
        .file("external/selinux/libsepol/src/kernel_to_conf.c")
        .file("external/selinux/libsepol/src/link.c")
        .file("external/selinux/libsepol/src/mls.c")
        .file("external/selinux/libsepol/src/module.c")
        .file("external/selinux/libsepol/src/module_to_cil.c")
        .file("external/selinux/libsepol/src/node_record.c")
        .file("external/selinux/libsepol/src/nodes.c")
        .file("external/selinux/libsepol/src/optimize.c")
        .file("external/selinux/libsepol/src/polcaps.c")
        // .file("external/selinux/libsepol/src/policydb.c")
        .file("external/selinux_hackery/src/policydb_wrapper.c")
        .file("external/selinux/libsepol/src/policydb_convert.c")
        .file("external/selinux/libsepol/src/policydb_public.c")
        .file("external/selinux/libsepol/src/policydb_validate.c")
        .file("external/selinux/libsepol/src/port_record.c")
        .file("external/selinux/libsepol/src/ports.c")
        .file("external/selinux/libsepol/src/services.c")
        .file("external/selinux/libsepol/src/sidtab.c")
        .file("external/selinux/libsepol/src/symtab.c")
        .file("external/selinux/libsepol/src/user_record.c")
        .file("external/selinux/libsepol/src/users.c")
        .file("external/selinux/libsepol/src/util.c")
        .file("external/selinux/libsepol/src/write.c")
        .file("external/selinux/libsepol/cil/src/android.c")
        .file("external/selinux/libsepol/cil/src/cil_binary.c")
        .file("external/selinux/libsepol/cil/src/cil_build_ast.c")
        .file("external/selinux/libsepol/cil/src/cil.c")
        .file("external/selinux/libsepol/cil/src/cil_copy_ast.c")
        .file("external/selinux/libsepol/cil/src/cil_find.c")
        .file("external/selinux/libsepol/cil/src/cil_fqn.c")
        // .file("external/selinux/libsepol/cil/src/cil_lexer.l")
        .file("external/selinux/libsepol/cil/src/cil_list.c")
        .file("external/selinux/libsepol/cil/src/cil_log.c")
        .file("external/selinux/libsepol/cil/src/cil_mem.c")
        .file("external/selinux/libsepol/cil/src/cil_parser.c")
        .file("external/selinux/libsepol/cil/src/cil_policy.c")
        .file("external/selinux/libsepol/cil/src/cil_post.c")
        .file("external/selinux/libsepol/cil/src/cil_reset_ast.c")
        .file("external/selinux/libsepol/cil/src/cil_resolve_ast.c")
        .file("external/selinux/libsepol/cil/src/cil_stack.c")
        .file("external/selinux/libsepol/cil/src/cil_strpool.c")
        .file("external/selinux/libsepol/cil/src/cil_symtab.c")
        .file("external/selinux/libsepol/cil/src/cil_tree.c")
        .file("external/selinux/libsepol/cil/src/cil_verify.c")
        .file("external/selinux/libsepol/cil/src/cil_write_ast.c")
        .file("external/selinux_hackery/src/handle_wrapper.c")
        .include("external/selinux/libsepol/cil/src")
        .include("external/selinux/libsepol/src")
        .include("external/selinux/libsepol/cil/include")
        .include("external/selinux/libsepol/include")
        .include("external/selinux_hackery/include")
        .define("HAVE_REALLOCARRAY", None)
        .define("_GNU_SOURCE", None)
        .flag("-Wall")
        .flag("-Werror")
        .flag("-W")
        .flag("-Wundef")
        .flag("-Wshadow")
        .flag("-Wno-error=missing-noreturn")
        .flag("-Wmissing-format-attribute")
        // These are needed to cancel out warnings enabled by the Android NDK.
        .flag("-Wno-assign-enum")
        .flag("-Wno-cast-align")
        .flag("-Wno-conditional-uninitialized")
        .flag("-Wno-implicit-fallthrough")
        .flag("-Wno-implicit-int-conversion")
        .flag("-Wno-missing-variable-declarations")
        .flag("-Wno-shorten-64-to-32")
        .flag("-Wno-sign-conversion")
        .flag("-Wno-unreachable-code-break")
        .flag("-Wno-unreachable-code-return")
        .flag("-Wno-unused-but-set-variable")
        // These reverse global warnings.
        .flag("-Wno-pedantic")
        .flag("-Wno-cast-qual")
        .flag("-Wno-conversion")
        .flag_if_supported("-Wno-duplicated-branches>")
        .flag_if_supported("-Wno-format-truncation>")
        .flag_if_supported("-Wno-jump-misses-init>")
        .flag("-Wno-missing-declarations")
        .flag("-Wno-missing-prototypes")
        .flag_if_supported("-Wno-calloc-transposed-args")
        .compile("sepol");
}

fn bind_libsepol() {
    println!("cargo:rerun-if-changed=external/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("external/wrapper.h")
        .clang_arg("-Iexternal/selinux/libsepol/cil/src")
        .clang_arg("-Iexternal/selinux/libsepol/src")
        .clang_arg("-Iexternal/selinux/libsepol/cil/include")
        .clang_arg("-Iexternal/selinux/libsepol/include")
        .clang_arg("-Iexternal/selinux_hackery/include")
        .allowlist_function("avtab_.*")
        .allowlist_function("ebitmap_.*")
        .allowlist_function("hashtab_.*")
        .allowlist_function("policydb_.*")
        .allowlist_function("sepol_.*")
        .allowlist_function("symtab_.*")
        .allowlist_function("type_datum_.*")
        .allowlist_type(".*_datum")
        .allowlist_type("ebitmap")
        .allowlist_type("msg_non_variadic_callback_data")
        .allowlist_type("policydb")
        .allowlist_var("AVTAB_.*")
        .allowlist_var("CEXPR_.*")
        .allowlist_var("POLICYDB_VERSION_.*")
        .allowlist_var("SCOPE_.*")
        .allowlist_var("SYM_.*")
        .allowlist_var("TYPE_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}

fn main() {
    build_libsepol();
    bind_libsepol();
}
