// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Visible tenant-document SOURCE boundary, approved scope 2026-11-06 10:05.
//! Inventories explicit tenants collection acquisitions and TenantDao/base
//! mutations, with previously reviewed creation/gateways and finite exceptions.
//! Read-only tenant access does not taint writes to users/agents/other stores.
//! This is not type safety, macro expansion, alias/dataflow or a runtime fence.
//!
//! Known generic capabilities OUTSIDE this gate, requiring manual review:
//! - api/growth/digest.rs::aggregate (collection + arbitrary pipeline).
//! - api/routes/account_devices.rs::aggregate_one (same).
//! - api/routes/stats.rs::agg (same).
//! - api/stats_rollup.rs::roll_family ($merge destination is in the pipeline).
//! - modules/vault/src/dao.rs::tombstone_row<T> (generic BaseDao write).
//! - services/src/dao/stats.rs::StatsDao::coll(name) (public raw handle).
//! A dynamic collection name, imported/type-disguised handle, out-of-line alias
//! or mutation hidden by macro expansion can evade this visible boundary.
//! Generic APIs and other document revisions are not sealed by this test.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Attribute, Item,
    visit::{self, Visit},
};
const DAO: &str = "crates/services/src/dao/tenant.rs";
const BASE: &str = "crates/services/src/dao/base.rs";
const STRIPE: &str = "crates/services/src/stripe.rs";

// Whole normalized bodies pin only the dynamic RC builders, DAO factory and
// finite payload exceptions. Gateway implementation belongs to behavior tests.
// Limited exceptions: DNS domain/nameservers + updated_at; keep-busy's two
// fields + updated_at. Stripe checkout only billing/customer_id; sync only
// billing.seats; subscription/process only billing/plan + updated_at, including
// status/cancel fields. ANY changed builder/operator/helper needs manual review.
#[rustfmt::skip]
const BODIES: &[(&str, &str, &str, &str)] = &[
    (DAO, "TenantDao", "new", "8c5036426b0ba25797b624101ee620c4ca6923913321d8688fbe806bd89b4361"),
    (DAO, "TenantDao", "set_rc_session_limits", "b4bd60ed959be0d03f7be3e4b14c7b056fe947af71029b3b859df2b8a10e13e7"),
    (DAO, "TenantDao", "set_rc_session_policy", "6077e4a63f3184cc0f34328f7d2bac00f8aaf7a267219b1f7c49218ffcb17ff5"),
    (DAO, "TenantDao", "set_magic_dns", "8f732a094cdb46cac367590f0cef427d9e96020f00f7f05ae09be558d549e2e4"),
    (DAO, "TenantDao", "set_keep_busy_settings", "4d1075f4f0cfa4e739d490f4c69809218e977eb1856d2b9e7475ceba7f85f9c4"),
    (STRIPE, "StripeService", "create_checkout_session", "5f3e0f47b97a164e26dd673dfef3187dbac2bdce2db4536231c2bbdfeecf1d96"),
    (STRIPE, "StripeService", "sync_seats", "947c00a263a9e8a3d1a6438e012ede8fc21a63cbd09b3f1dbd42f7b8de80dedf"),
    (STRIPE, "StripeService", "apply_subscription", "7ad9aade188b45fa466ccd44bfc5fec8331184cd4d4ba7d3dc6cc2743dc8f238"),
    (STRIPE, "StripeService", "process", "fc78007f966ee26e6b232c01da1970336375ac4e8491d2c52ccfbe091fb983c2"),
];
// Only public acquisition/mutation API SIGNATURES, not BaseDao implementation
// bodies. Existing behavior tests and review remain necessary for its internals.
#[rustfmt::skip]
const BASE_API: &[(&str, &str)] = &[
    ("new", "2e7c22c87840df3cce7a15d182c2091d4a7c8d8fc5b7bcca04c6ed27960932d1"),
    ("collection", "e85b628cd49e6550dca07ff1ff356b874aa26706fe6c128977dc33e6164d82d3"),
    ("insert_one", "d3cccc44fde87d51490875850778dbad60cefe6e34c9f75b50eddb928b17c92b"),
    ("update_one", "049dc2ffd82f121439757c482e9b71a7459544f64979292aec772a69749c99a5"),
    ("update_by_id", "ad35d71d413ae16d202bb702d77ab7486532154e4ef4014a0be9039269b2b8a9"),
    ("update_many", "bce2b4044a7f3ad1c369a923c16b26e5f5780e39d6a33bd0fb71c4e2e8d55175"),
    ("soft_delete", "7fad53739f7a78e72c09deff2bffe25c567a06a32ce4471f2d41ae68bcd12c05"),
    ("soft_delete_in_tenant", "07532939b909b41484940a04ef896c46e674ebad67f20853073f17e280635919"),
    ("hard_delete", "6a698fbdda49c3f9c9474a8ae687f571b3946b2472b9298e5e9b4a2ef002b5ad"),
];
// Existing behavior tests own gateway internals. Inventory the original
// mutation/delegation references, including both conditional CAS branches.
const GATEWAYS: &[(&str, &str, usize)] = &[
    ("update_security", "update_security_with_unset", 1),
    ("update_security_with_unset", "find_one_and_update", 2),
    ("create", "insert_one", 1),
];
const SCALARS: &[(&str, &str, &str)] = &[
    ("set_archived", "is_archived", "archived"),
    (
        "set_remote_exec_enabled",
        "settings.remote_exec_enabled",
        "enabled",
    ),
    (
        "set_exec_require_system",
        "settings.exec_require_system",
        "required",
    ),
    (
        "set_remote_ssh_enabled",
        "settings.remote_ssh_enabled",
        "enabled",
    ),
    (
        "set_ephemeral_keys_enabled",
        "settings.ephemeral_keys_enabled",
        "enabled",
    ),
    (
        "set_external_rc_enabled",
        "settings.external_rc_enabled",
        "enabled",
    ),
];

// Macro discovery only: transparent None groups preserve visible references,
// while real delimiters remain distinct. Exhaustive native variants handle
// lifetime apostrophes and keep a quoted string as one literal, without lexing.
fn tokens(stream: TokenStream, out: &mut Vec<String>) {
    for token in stream {
        match token {
            TokenTree::Group(group) => {
                let delimiters = match group.delimiter() {
                    Delimiter::Parenthesis => Some(("(", ")")),
                    Delimiter::Brace => Some(("{", "}")),
                    Delimiter::Bracket => Some(("[", "]")),
                    Delimiter::None => None,
                };
                if let Some((open, _)) = delimiters {
                    out.push(open.into());
                }
                tokens(group.stream(), out);
                if let Some((_, close)) = delimiters {
                    out.push(close.into());
                }
            }
            TokenTree::Ident(ident) => out.push(ident.to_string()),
            TokenTree::Punct(punct) => out.push(punct.as_char().to_string()),
            TokenTree::Literal(literal) => out.push(literal.to_string()),
        }
    }
}

// Only syn nodes parsed from source are fingerprinted, not arbitrary generated
// TokenStreams: Display does not preserve invisible None groups or negative
// Literal tokens. The 19 reviewed nodes contain neither. Standard Display is
// pinned by syn/quote/proc-macro2 and the review toolchain; changes require review
// and independent regeneration from the approved source, never blind rebasing.
fn fingerprint(node: &impl ToTokens) -> String {
    hex::encode(Sha256::digest(
        node.to_token_stream().to_string().as_bytes(),
    ))
}

// Omit only unmistakable test items. Complex/unknown cfg remains visible.
fn production(attrs: &[Attribute]) -> bool {
    !attrs.iter().any(|a| {
        a.path().is_ident("test")
            || a.path()
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                == ["tokio", "test"]
            || (a.path().is_ident("cfg")
                && a.parse_args::<syn::Path>()
                    .is_ok_and(|p| p.is_ident("test")))
    })
}

const WRITES: &[&str] = &[
    "insert_one",
    "insert_many",
    "update_one",
    "update_by_id",
    "update_many",
    "replace_one",
    "find_one_and_update",
    "find_one_and_replace",
    "delete_one",
    "delete_many",
    "soft_delete",
    "soft_delete_in_tenant",
    "hard_delete",
    "bulk_write",
    "aggregate",
];
#[derive(Default)]
struct Summary {
    acquired: bool,
    tenant_write: bool,
    escape: bool,
    writes: bool,
    operations: BTreeMap<String, usize>,
}
struct Facts<'a> {
    facts: Summary,
    models: &'a BTreeMap<String, String>,
    names: &'a BTreeSet<String>,
    owner: &'a str,
    file: &'a str,
}
impl Facts<'_> {
    fn tenant_name(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Lit(x) => matches!(&x.lit, syn::Lit::Str(s) if s.value() == "tenants"),
            syn::Expr::Path(p) => {
                let parts: Vec<_> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if parts.len() >= 2
                    && parts.last().is_some_and(|n| n == "COLLECTION")
                    && parts.iter().any(|n| self.names.contains(n))
                {
                    return true;
                }
                let model = parts
                    .get(parts.len().saturating_sub(2))
                    .map(String::as_str)
                    .unwrap_or("");
                let model = if model == "Self" { self.owner } else { model };
                let key = if parts.len() == 1 {
                    format!("{}::{}", self.file, parts[0])
                } else {
                    model.to_string()
                };
                self.models.get(&key).is_some_and(|s| s == "tenants")
            }
            _ => false, // Unknown names are a documented generic boundary.
        }
    }
    fn tenant_base(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Reference(r) => self.tenant_base(&r.expr),
            syn::Expr::Paren(p) => self.tenant_base(&p.expr),
            syn::Expr::Field(f) if matches!(&f.member, syn::Member::Named(n) if n == "base") => {
                matches!(f.base.as_ref(), syn::Expr::Field(t) if matches!(&t.member, syn::Member::Named(n) if n == "tenants"))
                    || (self.owner == "TenantDao"
                        && matches!(f.base.as_ref(), syn::Expr::Path(p) if p.path.is_ident("self")))
            }
            _ => false,
        }
    }
    fn acquisition(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Reference(r) => self.acquisition(&r.expr),
            syn::Expr::Paren(p) => self.acquisition(&p.expr),
            syn::Expr::MethodCall(c) if c.method == "collection" => {
                c.args.first().is_some_and(|a| self.tenant_name(a))
                    || (c.args.is_empty() && self.tenant_base(&c.receiver))
            }
            syn::Expr::MethodCall(c)
                if ["clone", "with_type", "clone_with_type"]
                    .contains(&c.method.to_string().as_str())
                    && c.args.is_empty() =>
            {
                self.acquisition(&c.receiver)
            }
            _ => self.tenant_base(expr),
        }
    }
}
impl<'ast> Visit<'ast> for Facts<'_> {
    fn visit_expr_path(&mut self, e: &'ast syn::ExprPath) {
        for name in e.path.segments.iter().map(|s| s.ident.to_string()) {
            if WRITES.contains(&name.as_str()) {
                self.facts.writes = true;
                *self.facts.operations.entry(name).or_default() += 1;
            }
        }
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        // An explicitly acquired handle plus a mutation in this function stays
        // conservative. This does not resolve alias identity or shadowing.
        if local
            .init
            .as_ref()
            .is_some_and(|i| self.acquisition(&i.expr))
        {
            self.facts.acquired = true;
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        let method = e.method.to_string();
        if WRITES.contains(&method.as_str())
            || method == "update_security"
            || method == "update_security_with_unset"
        {
            *self.facts.operations.entry(method.clone()).or_default() += 1;
        }
        if WRITES.contains(&method.as_str()) {
            self.facts.writes = true;
            if self.acquisition(&e.receiver) {
                self.facts.tenant_write = true;
            }
        }
        if e.method == "collection" && e.args.first().is_some_and(|a| self.tenant_name(a)) {
            self.facts.acquired = true;
        }
        if e.args.iter().any(|a| self.acquisition(a)) {
            self.facts.escape = true;
        }
        visit::visit_expr_method_call(self, e);
    }
    fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
        if e.args.iter().any(|a| self.acquisition(a)) {
            self.facts.escape = true;
        }
        if let syn::Expr::Path(p) = e.func.as_ref() {
            let parts: Vec<_> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if parts.ends_with(&["BaseDao".into(), "new".into()])
                && e.args.len() > 1
                && self.tenant_name(&e.args[1])
            {
                self.facts.acquired = true;
            }
        }
        visit::visit_expr_call(self, e);
    }
    fn visit_macro(&mut self, e: &'ast syn::Macro) {
        let mut t = Vec::new();
        tokens(e.tokens.clone(), &mut t);
        // Only literal collection calls or a nominal Tenant::COLLECTION call
        // are visible acquisitions; mentioning Tenant in a lookup is a read.
        let collection_call = t.windows(2).any(|w| w == ["collection", "("])
            || t.windows(2).any(|w| w == ["collection", ":"]);
        if collection_call
            && (t.iter().any(|n| n == "\"tenants\"")
                || (t.iter().any(|n| self.names.contains(n))
                    && t.iter().any(|n| n == "COLLECTION")))
        {
            self.facts.acquired = true;
        }
        if t.windows(3).any(|w| w == ["tenants", ".", "base"])
            || (self.owner == "TenantDao" && t.windows(3).any(|w| w == ["self", ".", "base"]))
        {
            self.facts.acquired = true;
        }
        for name in t.iter().filter(|n| WRITES.contains(&n.as_str())) {
            self.facts.writes = true;
            *self.facts.operations.entry(name.clone()).or_default() += 1;
        }
    }
}

// Same-module nominal schema collection literals, not a Rust type resolver.
fn models(items: &[Item], file: &str, into: &mut BTreeMap<String, String>) {
    fn literal(into: &mut BTreeMap<String, String>, key: String, value: String) {
        let value = if into.get(&key).is_some_and(|old| *old != value) {
            "<ambiguous>".into()
        } else {
            value
        };
        into.insert(key, value);
    }
    for item in items {
        if let Item::Const(c) = item {
            if let syn::Expr::Lit(e) = &*c.expr {
                if let syn::Lit::Str(v) = &e.lit {
                    literal(into, format!("{file}::{}", c.ident), v.value());
                }
            }
        }
        if let Item::Impl(i) = item {
            if !production(&i.attrs) {
                continue;
            }
            if let syn::Type::Path(p) = i.self_ty.as_ref() {
                if let Some(name) = p.path.segments.last() {
                    for member in &i.items {
                        if let syn::ImplItem::Const(c) = member {
                            if c.ident == "COLLECTION" {
                                if let syn::Expr::Lit(e) = &c.expr {
                                    if let syn::Lit::Str(s) = &e.lit {
                                        literal(into, name.ident.to_string(), s.value());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Item::Mod(m) = item {
            if !production(&m.attrs) {
                continue;
            }
            if let Some((_, children)) = &m.content {
                models(children, file, into);
            }
        }
    }
}

struct Check<'a> {
    file: &'a str,
    owner: String,
    models: &'a BTreeMap<String, String>,
    names: BTreeSet<String>,
    seen: BTreeSet<String>,
    interfaces: BTreeMap<String, String>,
    errors: Vec<String>,
}
impl Check<'_> {
    fn function(
        &mut self,
        sig: &syn::Signature,
        attrs: &[Attribute],
        body: &syn::Block,
        public: bool,
    ) {
        if !production(attrs) {
            return;
        }
        let mut f = Facts {
            facts: Summary::default(),
            models: self.models,
            names: &self.names,
            owner: &self.owner,
            file: self.file,
        };
        f.visit_block(body);
        let name = sig.ident.to_string();
        if self.file == BASE && self.owner == "BaseDao" {
            if public
                && (name == "new"
                    || sig
                        .output
                        .to_token_stream()
                        .to_string()
                        .contains("Collection")
                    || f.facts.writes)
            {
                if self.interfaces.insert(name, fingerprint(sig)).is_some() {
                    self.errors
                        .push("duplicate/conditional BaseDao interface requires review".into());
                }
            }
            return; // only interfaces, explicitly no implementation proof
        }
        if self.file == DAO && self.owner == "TenantDao" {
            if let Some((_, field, value)) = SCALARS.iter().find(|(method, _, _)| *method == name) {
                // Exact single-expression delegate, parsed by native syn.
                let expected: syn::Block = syn::parse_str(&format!(
                    r#"{{ self.update_security(tenant_id, doc!{{"{field}": {value}}}).await }}"#
                ))
                .unwrap();
                self.seen.insert(format!("scalar::{name}"));
                if fingerprint(body) != fingerprint(&expected) {
                    self.errors
                        .push(format!("{name}: scalar field/gateway shape changed"));
                }
                return;
            }
            if let Some((_, operation, count)) =
                GATEWAYS.iter().find(|(method, _, _)| *method == name)
            {
                self.seen.insert(format!("gateway::{name}"));
                if f.facts.operations != BTreeMap::from([(operation.to_string(), *count)]) {
                    self.errors
                        .push(format!("{name}: mutation/delegation inventory changed"));
                }
                return;
            }
        }
        if let Some((_, _, _, expected)) = BODIES.iter().find(|(file, owner, method, _)| {
            *file == self.file && *owner == self.owner && *method == name
        }) {
            self.seen
                .insert(format!("{}::{}::{}", self.file, self.owner, name));
            if fingerprint(body) != *expected {
                self.errors.push(format!(
                    "reviewed {name} payload changed; scope requires review"
                ));
            }
            return;
        }
        let s = &f.facts;
        let returns_handle = sig
            .output
            .to_token_stream()
            .to_string()
            .contains("Collection")
            || sig.output.to_token_stream().to_string().contains("BaseDao");
        let new_gateway = self.owner == "TenantDao"
            && ["update_security", "update_security_with_unset"]
                .iter()
                .any(|n| s.operations.contains_key(*n));
        if new_gateway || s.tenant_write || s.escape || (s.acquired && (s.writes || returns_handle))
        {
            self.errors.push(format!(
                "unreviewed visible tenant mutation/handle: {}::{name}",
                self.owner
            ));
        }
    }
}
impl<'ast> Visit<'ast> for Check<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        let attrs = match item {
            Item::Fn(x) => &x.attrs,
            Item::Impl(x) => &x.attrs,
            Item::Mod(x) => &x.attrs,
            Item::Trait(x) => &x.attrs,
            _ => {
                visit::visit_item(self, item);
                return;
            }
        };
        if !production(attrs) {
            return;
        }
        visit::visit_item(self, item);
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let previous = self.owner.clone();
        self.owner = if let syn::Type::Path(p) = item.self_ty.as_ref() {
            p.path.segments.last().unwrap().ident.to_string()
        } else {
            String::new()
        };
        visit::visit_item_impl(self, item);
        self.owner = previous;
    }
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.function(
            &i.sig,
            &i.attrs,
            &i.block,
            matches!(i.vis, syn::Visibility::Public(_)),
        );
    }
    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.function(
            &i.sig,
            &i.attrs,
            &i.block,
            matches!(i.vis, syn::Visibility::Public(_)),
        );
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(block) = &item.default {
            self.function(&item.sig, &item.attrs, block, false);
        }
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        fn aliases(t: &syn::UseTree, n: &mut BTreeSet<String>) {
            match t {
                syn::UseTree::Rename(x) if x.ident == "Tenant" => {
                    n.insert(x.rename.to_string());
                }
                syn::UseTree::Path(x) => aliases(&x.tree, n),
                syn::UseTree::Group(x) => {
                    for c in &x.items {
                        aliases(c, n);
                    }
                }
                _ => {}
            }
        }
        aliases(&item.tree, &mut self.names);
    }
}
fn scan(
    file: &str,
    source: &str,
    schema: &BTreeMap<String, String>,
) -> Result<(BTreeSet<String>, BTreeMap<String, String>), String> {
    let ast = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut c = Check {
        file,
        owner: String::new(),
        models: schema,
        names: BTreeSet::from(["Tenant".into()]),
        seen: BTreeSet::new(),
        interfaces: BTreeMap::new(),
        errors: Vec::new(),
    };
    for item in &ast.items {
        if let Item::Use(i) = item {
            c.visit_item_use(i);
        }
    }
    c.visit_file(&ast);
    if c.errors.is_empty() {
        Ok((c.seen, c.interfaces))
    } else {
        Err(format!("{file}: {:?}", c.errors))
    }
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

#[test]
fn tenant_writes_have_only_reviewed_owners_and_payloads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    sources(&root, &root, &mut files).unwrap();
    assert!(files.len() >= 100);
    let mut schema = BTreeMap::new();
    for file in &files {
        models(
            &syn::parse_file(&fs::read_to_string(file).unwrap())
                .unwrap()
                .items,
            file.strip_prefix(&root).unwrap().to_str().unwrap(),
            &mut schema,
        );
    }
    let mut seen = BTreeSet::new();
    let mut api = BTreeMap::new();
    for file in files {
        let relative = file.strip_prefix(&root).unwrap().to_str().unwrap();
        let (s, a) = scan(relative, &fs::read_to_string(&file).unwrap(), &schema).unwrap();
        seen.extend(s);
        for (k, v) in a {
            assert!(api.insert(k, v).is_none(), "duplicate BaseDao interface");
        }
    }
    let expected: BTreeSet<_> = BODIES
        .iter()
        .map(|(f, o, n, _)| format!("{f}::{o}::{n}"))
        .chain(SCALARS.iter().map(|(n, _, _)| format!("scalar::{n}")))
        .chain(GATEWAYS.iter().map(|(n, _, _)| format!("gateway::{n}")))
        .collect();
    assert_eq!(seen, expected);
    assert_eq!(
        api,
        BASE_API
            .iter()
            .map(|(n, h)| (n.to_string(), h.to_string()))
            .collect()
    );
}
#[test]
fn new_writers_aliases_dynamic_payloads_and_handle_escapes_require_review() {
    for source in [
        r#"fn f(db:&Database){let c=db.collection::<Document>("tenants");let alias=c;alias.update_one(filter,update);}"#,
        r#"fn f(state:&State){state.tenants.base.update_by_id(id,doc!{"$set":{"owner_id":owner,"settings.mfa_required":false}});}"#,
        r#"fn f(db:&Database){db.collection::<Document>("tenants").replace_one(filter,replacement);}"#,
        r#"fn f(db:&Database){db.collection::<Document>("tenants").update_one(filter,doc!{"$set":{"settings":replacement}});}"#,
        r#"fn f(db:&Database){db.collection::<Document>("tenants").update_one(filter,vec![doc!{"$set":{"settings.remote_ssh_enabled":true}}]);}"#,
        r#"fn f(db:&Database){unknown_fn(db.collection::<Document>("tenants"));}"#,
        r#"fn f(state:&State){unknown_fn(&state.tenants.base);}"#,
        r#"trait Hidden { fn f(&self) { db.collection::<Document>("tenants").update_one(filter,update); } }"#,
        r#"fn f(db:&Database){let value=doc!{"x":db.collection::<Document>("tenants").update_one(filter,update)};}"#,
        r#"fn f(state:&State){state.tenants.base.soft_delete(id);state.tenants.base.hard_delete(filter);}"#,
        r#"fn f(state:&State){let write=BaseDao::update_one;write(&state.tenants.base,filter,update);}"#,
        r#"use models::Tenant as T;fn f(db:&Database){db.collection::<T>(T::COLLECTION).delete_many(filter);}"#,
        r#"impl TenantDao { fn bypass(&self) { self.base.update_by_id(id,doc!{"$set":{"settings.mfa_required":false}}); } }"#,
        r#"impl TenantDao { fn new_policy(&self) { self.update_security(id,doc!{"owner_id":owner}); } }"#,
        r#"fn f(state:&State){state.tenants.base.collection().clone_with_type::<Document>().update_one(filter,update);}"#,
        r#"fn f(db:&Database)->Collection<Document>{db.collection::<Document>("tenants")}"#,
    ] {
        assert!(
            scan("unreviewed.rs", source, &BTreeMap::new()).is_err(),
            "{source}"
        );
    }
    assert!(scan("bad.rs", "fn broken(", &BTreeMap::new()).is_err());
}
#[test]
fn obvious_reads_comments_and_test_items_are_not_writers() {
    let source = r##"
    // state.tenants.base.update_by_id(id,update);
    const TEXT:&str="tenant mutation update_one";
    #[cfg(test)] mod tests{fn helper(){state.tenants.base.soft_delete(id);}}
    #[tokio::test] async fn test_only(){state.tenants.base.update_one(filter,update);}
    fn read(state:&State){state.tenants.base.find_by_id(id);}
    fn query(db:&Database){let c=db.collection::<Document>("tenants");let alias=c;alias.find_one(filter);}
    fn count(db:&Database){db.collection::<Document>("tenants").count_documents(filter);}
    "##;
    scan("read.rs", source, &BTreeMap::new()).unwrap();
}
#[test]
fn same_name_exceptions_cannot_add_security_fields_or_operators() {
    fn selected(file: &str, source: &str) -> String {
        let mut ast = syn::parse_file(source).unwrap();
        ast.items.retain_mut(|item| {
            let Item::Impl(i) = item else { return false; };
            let syn::Type::Path(owner) = i.self_ty.as_ref() else { return false; };
            let owner = owner.path.segments.last().unwrap().ident.to_string();
            i.items.retain(|member| matches!(member, syn::ImplItem::Fn(f) if BODIES.iter().any(|(p,o,n,_)| *p==file && *o==owner && *n==f.sig.ident.to_string() || (file == DAO && owner == "TenantDao" && (SCALARS.iter().any(|(n,_,_)| *n==f.sig.ident.to_string()) || GATEWAYS.iter().any(|(n,_,_)| *n==f.sig.ident.to_string()))))));
            !i.items.is_empty()
        });
        ast.to_token_stream().to_string()
    }
    let dao = selected(DAO, include_str!("../src/dao/tenant.rs"));
    let stripe = selected(STRIPE, include_str!("../src/stripe.rs"));
    scan(DAO, &dao, &BTreeMap::new()).unwrap();
    scan(STRIPE, &stripe, &BTreeMap::new()).unwrap();
    for changed in [
        dao.replace("settings.magic_dns_domain", "settings.remote_ssh_enabled"),
        dao.replace("settings.keep_busy_denied", "settings.mfa_required"),
        dao.replace("settings.remote_ssh_enabled", "security_rev"),
        dao.replace(r#""$set""#, r#""$rename""#),
    ] {
        assert!(scan(DAO, &changed, &BTreeMap::new()).is_err());
    }
    assert!(
        scan(
            STRIPE,
            &stripe.replace(r#""billing.seats""#, r#""settings.remote_ssh_enabled""#),
            &BTreeMap::new()
        )
        .is_err()
    );
}

#[test]
fn base_public_interface_discovery_does_not_pin_implementation_bodies() {
    let first =
        "impl<T> BaseDao<T> { pub fn collection(&self) -> &Collection<T> { &self.collection } }";
    let body_only = first.replace("&self.collection }", "{ let _note=(); &self.collection } }");
    let (_, original) = scan(BASE, first, &BTreeMap::new()).unwrap();
    let (_, same_api) = scan(BASE, &body_only, &BTreeMap::new()).unwrap();
    assert_eq!(original, same_api);
    let changed = first.replace("&self)", "&mut self)");
    let (_, changed_api) = scan(BASE, &changed, &BTreeMap::new()).unwrap();
    assert_ne!(original["collection"], changed_api["collection"]);
    let novel = "impl<T> BaseDao<T> { pub async fn new_writer(&self) { self.collection.update_one(filter, update).await; } }";
    let (_, api) = scan(BASE, novel, &BTreeMap::new()).unwrap();
    assert!(api.contains_key("new_writer"));
    assert!(!BASE_API.iter().any(|(name, _)| *name == "new_writer"));
}

#[test]
fn normalization_retains_parenthesis_boundaries() {
    let first: syn::Expr = syn::parse_str("a * (b + c)").unwrap();
    let second: syn::Expr = syn::parse_str("(a * b) + c").unwrap();
    assert_ne!(fingerprint(&first), fingerprint(&second));
}

#[test]
fn native_tokens_cover_lifetimes_groups_and_literal_boundaries() {
    for source in [
        "'label: loop { let x: &'a str = \"x y\"; break 'label; }",
        "f::<Vec<Vec<u8>>>(g((1, 2)), \"a b\")",
        "-1i64",
        "'a'",
    ] {
        let expr: syn::Expr = syn::parse_str(source).unwrap();
        let displayed = expr.to_token_stream().to_string();
        let reparsed: syn::Expr = syn::parse_str(&displayed).unwrap();
        assert_eq!(fingerprint(&expr), fingerprint(&reparsed));
        let mut visible = Vec::new();
        tokens(expr.to_token_stream(), &mut visible);
        assert!(!visible.is_empty());
    }
    let mut visible = Vec::new();
    tokens(
        "f(\"update_one tenants base\", ('label, -1))"
            .parse()
            .unwrap(),
        &mut visible,
    );
    assert!(visible.iter().any(|s| s == "\"update_one tenants base\""));
    assert!(!visible.iter().any(|s| s == "update_one"));
    assert_eq!(visible.iter().filter(|s| s.as_str() == "(").count(), 2);
    assert!(visible.windows(2).any(|s| s == ["'", "label"]));

    // Standard Display intentionally is not injective for arbitrary generated
    // tokens. Such streams are outside fingerprint's source-node contract.
    let ordinary: TokenStream = "a + b".parse().unwrap();
    let invisible = TokenStream::from(TokenTree::Group(proc_macro2::Group::new(
        Delimiter::None,
        ordinary.clone(),
    )));
    assert_eq!(ordinary.to_string(), invisible.to_string());
    assert_eq!(ordinary.into_iter().count(), 3);
    assert_eq!(invisible.clone().into_iter().count(), 1);
    let mut visible = Vec::new();
    tokens(invisible, &mut visible);
    assert_eq!(visible, ["a", "+", "b"]);
    // Negative Literal constructors may split through TokenStream conversion.
    // Our supported source input instead parses as unary minus plus an integer;
    // assert that exact value, sign and suffix survive the standard printer.
    let negative: syn::Expr = syn::parse_str("-1i64").unwrap();
    let reparsed: syn::Expr = syn::parse_str(&negative.to_token_stream().to_string()).unwrap();
    for expr in [&negative, &reparsed] {
        let syn::Expr::Unary(unary) = expr else {
            panic!("source negative must remain a unary expression");
        };
        assert!(matches!(unary.op, syn::UnOp::Neg(_)));
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(integer),
            ..
        }) = unary.expr.as_ref()
        else {
            panic!("source negative must retain its integer operand");
        };
        assert_eq!(integer.base10_digits(), "1");
        assert_eq!(integer.suffix(), "i64");
    }
    let positive: syn::Expr = syn::parse_str("1i64").unwrap();
    assert_eq!(fingerprint(&negative), fingerprint(&reparsed));
    assert_ne!(fingerprint(&negative), fingerprint(&positive));
}

#[test]
fn visible_scope_separates_other_stores_and_documents_generic_limits() {
    // These are outside the explicit tenant-document mutation boundary, not
    // evidence that their authorization, pipeline or generic API is safe.
    for source in [
        r#"fn register(state:&State){state.users.base.update_by_id(id,doc!{"$set":{"is_verified":true}});state.tenants.create(name,slug,id);}"#,
        r#"fn f(state:&State){state.tenants.base.find_by_id(id);state.agents.base.update_by_id(id,doc!{"$set":{"exec_anchor":anchor}});}"#,
        r#"fn f(state:&State){state.tenants.is_member(id,user);state.files.soft_delete(id,file);}"#,
        r#"fn f(set:&ExclusionSet,state:&State){set.tenants.contains(&id);state.messages.base.update_by_id(id,update);}"#,
        r#"fn f(state:&State){state.tenants.members.collection().find(filter);}"#,
        r#"fn f(db:&Database){db.collection::<Tenant>(Tenant::COLLECTION).find_one(filter);}"#,
        r#"fn aggregate(db:&Database,name:&str,pipeline:Vec<Document>){db.collection::<Document>(name).aggregate(pipeline);}"#,
        r#"fn tombstone<T>(base:&BaseDao<T>){base.collection().update_one(filter,update);}"#,
        r#"fn coll(db:&Database,name:&str)->Collection<Document>{db.collection::<Document>(name)}"#,
        r#"fn f(db:&Database){let alias=hidden_factory(db);alias.update_one(filter,update);}"#,
        r#"fn f(db:&Database){hidden_write!(db);}"#,
    ] {
        scan("visible-scope.rs", source, &BTreeMap::new()).unwrap();
    }
}
