// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Source architecture gate, not a Rust visibility/security boundary. Unknown
//! cfgs are scanned conservatively. This does not expand macros, resolve types,
//! or inspect dynamically generated/out-of-tree code. Macro tokens containing
//! the explicit privileged identifier are rejected outside the allowed caller.

use std::{
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Attribute, Item, Meta, Token,
    punctuated::Punctuated,
    visit::{self, Visit},
};

const ENTRY: &str = "dispatch_local_pdp_session_request";
const CALLER: &str = "crates/modules/remote/src/controller.rs";

// Only definitely test-only cfgs are omitted. Every other target/feature is a
// possible production build, including cfg expressions we cannot prove false.
fn cfg_value(meta: &Meta) -> Result<Option<bool>, String> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Ok(Some(false)),
        Meta::NameValue(value) if value.path.is_ident("feature") => {
            let syn::Expr::Lit(value) = &value.value else {
                return Err("invalid cfg feature value".into());
            };
            let syn::Lit::Str(value) = &value.lit else {
                return Err("invalid cfg feature literal".into());
            };
            Ok((value.value() == "test-fixtures").then_some(false))
        }
        Meta::List(list)
            if list.path.is_ident("all")
                || list.path.is_ident("any")
                || list.path.is_ident("not") =>
        {
            let values = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|e| e.to_string())?
                .iter()
                .map(cfg_value)
                .collect::<Result<Vec<_>, _>>()?;
            if list.path.is_ident("not") {
                if values.len() != 1 {
                    return Err("invalid cfg not arity".into());
                }
                Ok(values[0].map(|v| !v))
            } else if list.path.is_ident("all") {
                Ok(if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|v| *v == Some(true)) {
                    Some(true)
                } else {
                    None
                })
            } else {
                Ok(if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|v| *v == Some(false)) {
                    Some(false)
                } else {
                    None
                })
            }
        }
        _ => Ok(None),
    }
}

fn production(attrs: &[Attribute]) -> Result<bool, String> {
    for attr in attrs {
        let path = attr.path();
        let tokio_test = path.segments.len() == 2
            && path.segments[0].ident == "tokio"
            && path.segments[1].ident == "test";
        if path.is_ident("test") || tokio_test {
            return Ok(false);
        }
        if path.is_ident("cfg")
            && cfg_value(&attr.parse_args::<Meta>().map_err(|e| e.to_string())?)? == Some(false)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mentions_entry(mut cursor: syn::buffer::Cursor<'_>) -> bool {
    while !cursor.eof() {
        if let Some((ident, next)) = cursor.ident() {
            if ident == ENTRY {
                return true;
            }
            cursor = next;
        } else if let Some((group, _, _, next)) = cursor.any_group() {
            if mentions_entry(group) {
                return true;
            }
            cursor = next;
        } else {
            cursor = cursor.token_tree().expect("nonempty token cursor").1;
        }
    }
    false
}

#[derive(Default)]
struct References {
    count: usize,
    error: Option<String>,
}
impl References {
    fn include(&mut self, attrs: &[Attribute]) -> bool {
        match production(attrs) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }
}
impl<'ast> Visit<'ast> for References {
    fn visit_item(&mut self, item: &'ast Item) {
        let attrs = match item {
            Item::Const(x) => &x.attrs,
            Item::Enum(x) => &x.attrs,
            Item::ExternCrate(x) => &x.attrs,
            Item::Fn(x) => &x.attrs,
            Item::ForeignMod(x) => &x.attrs,
            Item::Impl(x) => &x.attrs,
            Item::Macro(x) => &x.attrs,
            Item::Mod(x) => &x.attrs,
            Item::Static(x) => &x.attrs,
            Item::Struct(x) => &x.attrs,
            Item::Trait(x) => &x.attrs,
            Item::TraitAlias(x) => &x.attrs,
            Item::Type(x) => &x.attrs,
            Item::Union(x) => &x.attrs,
            Item::Use(x) => &x.attrs,
            Item::Verbatim(_) => {
                self.error = Some("unsupported production item syntax".into());
                return;
            }
            _ => {
                visit::visit_item(self, item);
                return;
            }
        };
        if self.include(attrs) {
            visit::visit_item(self, item);
        }
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(x) => &x.attrs,
            syn::ImplItem::Fn(x) => &x.attrs,
            syn::ImplItem::Type(x) => &x.attrs,
            syn::ImplItem::Macro(x) => &x.attrs,
            _ => {
                self.error = Some("unsupported production impl syntax".into());
                return;
            }
        };
        if self.include(attrs) {
            visit::visit_impl_item(self, item);
        }
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = match item {
            syn::TraitItem::Const(x) => &x.attrs,
            syn::TraitItem::Fn(x) => &x.attrs,
            syn::TraitItem::Type(x) => &x.attrs,
            syn::TraitItem::Macro(x) => &x.attrs,
            _ => {
                self.error = Some("unsupported production trait syntax".into());
                return;
            }
        };
        if self.include(attrs) {
            visit::visit_trait_item(self, item);
        }
    }
    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        if expr.method == ENTRY {
            self.count += 1;
        }
        visit::visit_expr_method_call(self, expr);
    }
    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        // Also catches UFCS and taking the associated function as a value.
        if expr.path.segments.iter().any(|s| s.ident == ENTRY) {
            self.count += 1;
        }
        visit::visit_expr_path(self, expr);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mentions_entry(syn::buffer::TokenBuffer::new2(mac.tokens.clone()).begin()) {
            self.count += 1;
        }
    }
}

fn references(source: &str) -> Result<usize, String> {
    let file = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut refs = References::default();
    if refs.include(&file.attrs) {
        refs.visit_file(&file);
    }
    refs.error.map_or(Ok(refs.count), Err)
}

fn sources(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        if [".git", "target", "node_modules", ".codex-evidence"]
            .iter()
            .any(|n| name == *n)
        {
            continue;
        }
        // Cargo's integration-test/benchmark roots and this workspace's test
        // library are not production callers. Other directories are included.
        if path == root.join("crates/tests")
            || ((name == "tests" || name == "benches") && dir.join("Cargo.toml").is_file())
        {
            continue;
        }
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_symlink() {
            return Err(format!(
                "source traversal refuses symlink {}",
                path.display()
            ));
        }
        if kind.is_dir() {
            sources(root, &path, out)?;
        } else if kind.is_file() && path.extension().is_some_and(|s| s == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn enforce(root: &Path, minimum_files: usize) -> Result<(), String> {
    let mut files = Vec::new();
    sources(root, root, &mut files)?;
    if files.len() < minimum_files {
        return Err(format!("scan too small: {} < {minimum_files}", files.len()));
    }
    files.sort();
    let mut actual = Vec::new();
    for file in files {
        let count = references(&fs::read_to_string(&file).map_err(|e| e.to_string())?)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        if count != 0 {
            actual.push((
                file.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
                count,
            ));
        }
    }
    let expected = vec![(PathBuf::from(CALLER), 1)];
    if actual != expected {
        return Err(format!(
            "trusted source entry references: {actual:?}; expected {expected:?}"
        ));
    }
    Ok(())
}

#[test]
fn only_local_controller_pdp_calls_trusted_file_child_creation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    enforce(&root, 100).unwrap();
}

#[test]
fn source_reference_parser_distinguishes_tests_literals_cfg_and_explicit_macro_tokens() {
    let ignored = r####"
        // hub.dispatch_local_pdp_session_request(ctx, msg);
        const TEXT: &str = r###"dispatch_local_pdp_session_request"###;
        #[cfg(test)] mod tests { fn helper() { hub.dispatch_local_pdp_session_request(ctx, msg); } }
        #[test] fn unit() { Hub::dispatch_local_pdp_session_request(hub, ctx, msg); }
        #[tokio::test] async fn async_unit() { hub.dispatch_local_pdp_session_request(ctx, msg); }
        #[cfg(any(test, feature = "test-fixtures"))] fn fixture() { hub.dispatch_local_pdp_session_request(ctx, msg); }
        fn harmless() { println!("dispatch_local_pdp_session_request"); }
    "####;
    assert_eq!(references(ignored).unwrap(), 0);
    for source in [
        "fn f() { hub\n . dispatch_local_pdp_session_request(ctx, msg); }",
        "fn f() { Hub::dispatch_local_pdp_session_request(hub, ctx, msg); }",
        "fn f() { let entry = Hub::dispatch_local_pdp_session_request; entry(hub, ctx, msg); }",
        "#[cfg(all(unix, not(test)))] fn f() { hub.dispatch_local_pdp_session_request(ctx, msg); }",
        "#[cfg(feature = \"future-production\")] fn f() { hub.dispatch_local_pdp_session_request(ctx, msg); }",
        "fn f() { generate!({ hub.dispatch_local_pdp_session_request(ctx, msg); }); }",
    ] {
        assert_eq!(references(source).unwrap(), 1, "{source}");
    }
    assert!(references("fn broken(").is_err());
    assert!(references("#[cfg(not(test, unix))] fn invalid() {}").is_err());
}

#[test]
fn source_inventory_rejects_extra_files_bad_source_missing_roots_and_short_scans() {
    struct Workspace(PathBuf);
    impl Drop for Workspace {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let root = std::env::temp_dir().join(format!("x14-source-boundary-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let workspace = Workspace(root);
    let caller = workspace.0.join(CALLER);
    fs::create_dir_all(caller.parent().unwrap()).unwrap();
    fs::write(
        &caller,
        "fn local() { hub.dispatch_local_pdp_session_request(ctx, msg); }",
    )
    .unwrap();
    enforce(&workspace.0, 1).unwrap();
    let other = workspace.0.join("unexpected.rs");
    for source in [
        "fn f() { hub\n.dispatch_local_pdp_session_request(ctx, msg); }",
        "fn f() { Hub::dispatch_local_pdp_session_request(hub, ctx, msg); }",
    ] {
        fs::write(&other, source).unwrap();
        assert!(enforce(&workspace.0, 1).is_err());
    }
    fs::write(&other, "fn harmless() {}").unwrap();
    enforce(&workspace.0, 2).unwrap();
    assert!(enforce(&workspace.0, 3).is_err());
    fs::write(&other, "fn invalid(").unwrap();
    assert!(enforce(&workspace.0, 1).is_err());
    fs::remove_file(&other).unwrap();
    assert!(enforce(&workspace.0.join("missing"), 1).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&caller, &other).unwrap();
        assert!(enforce(&workspace.0, 1).is_err());
    }
}
