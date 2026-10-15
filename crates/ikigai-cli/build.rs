//! Records which `ikigai-*` crates this binary links, and at which versions, for `ikigai
//! --version --verbose` (ledger #1338).
//!
//! The answer comes from the `Cargo.lock` this build resolved against, read here at build
//! time, so it is the binary's own record and not a guess made later from outside it. The
//! alternative it replaces read crates.io source paths out of the binary's panic locations,
//! which holds only while nothing builds with `-Zlocation-detail=none` and says nothing at all
//! for a path or git dependency.
//!
//! The lock alone over-reports. It is one resolve for the whole workspace: every member's
//! dev-dependencies are in it, and every optional dependency some feature could turn on. So
//! the walk starts at this package and follows, for each workspace member it reaches, only
//! the NORMAL dependencies its manifest declares (never `[dev-dependencies]` or
//! `[build-dependencies]`, neither of which is linked), and an optional one only when a
//! feature this build enabled turns it on, features followed through the members the way
//! Cargo unifies them. A crate from a registry is followed by its edges in the lock, which
//! lists only the dependencies its resolve activated.
//!
//! What it cannot see, stated so nobody reads more into the list than it says:
//!
//! - a target-specific dependency (`[target.'cfg(…)'.dependencies]`) is counted on every
//!   target. No `ikigai-*` crate is target-gated in this workspace today;
//! - a registry crate's edges in the lock are taken whole: an optional dependency the
//!   WORKSPACE resolve activated but this binary's features did not is counted, and so is a
//!   build-dependency, because the lock records neither which consumer activated an edge nor
//!   its kind;
//! - `cargo install` WITHOUT `--locked` resolves afresh and ignores the packaged lock, so the
//!   lock read here may not be the resolve that compiled. Install with `--locked` (every
//!   runbook here does) and the two are the same lock.
//!
//! The output is `OUT_DIR/linked-ikigai.txt`: one `name version` line per crate, sorted, or a
//! single line beginning `unknown:` that says why the list could not be made. A build never
//! fails over it: the version flag answers either way.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    let text = match linked(&manifest_dir) {
        Ok(crates) if crates.is_empty() => "unknown: no ikigai-* crate in the lock\n".to_string(),
        Ok(crates) => crates
            .iter()
            .map(|(name, version)| format!("{name} {version}\n"))
            .collect(),
        Err(why) => format!("unknown: {why}\n"),
    };
    std::fs::write(out_dir.join("linked-ikigai.txt"), text).expect("OUT_DIR is writable");
}

/// One `[[package]]` of the lock.
struct Locked {
    name: String,
    version: String,
    /// A workspace member (or a `[patch]` path): no `source` in the lock.
    path: bool,
    dependencies: Vec<String>,
}

/// The `(name, version)` of every `ikigai-*` crate this package links, itself excluded.
fn linked(manifest_dir: &Path) -> Result<BTreeSet<(String, String)>, String> {
    let lock_path = manifest_dir
        .ancestors()
        .map(|dir| dir.join("Cargo.lock"))
        .find(|path| path.is_file())
        .ok_or("no Cargo.lock beside this package or above it")?;
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let root = lock_path.parent().expect("a file has a parent");
    let lock = read_toml(&lock_path)?;
    let packages: Vec<Locked> = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("the lock has no [[package]] table")?
        .iter()
        .filter_map(|p| {
            Some(Locked {
                name: p.get("name")?.as_str()?.to_string(),
                version: p.get("version")?.as_str()?.to_string(),
                path: p.get("source").is_none(),
                dependencies: p
                    .get("dependencies")
                    .and_then(toml::Value::as_array)
                    .map(|deps| {
                        deps.iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect();

    let members = member_manifests(root)?;
    let workspace_deps = read_toml(&root.join("Cargo.toml"))
        .ok()
        .and_then(|t| t.get("workspace")?.get("dependencies")?.as_table().cloned())
        .unwrap_or_default();

    let this = std::env::var("CARGO_PKG_NAME").expect("set by cargo");
    let this_version = std::env::var("CARGO_PKG_VERSION").expect("set by cargo");
    let start = packages
        .iter()
        .position(|p| p.path && p.name == this && p.version == this_version)
        .ok_or_else(|| format!("{this} {this_version} is not in {}", lock_path.display()))?;
    let start_features = enabled_features(members.get(&this));

    // A member is revisited whenever its feature set grows, which is Cargo's unification;
    // a registry crate is visited once, since its edges in the lock do not depend on it.
    let mut member_features: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut seen_registry: BTreeSet<usize> = BTreeSet::new();
    let mut work: Vec<(usize, BTreeSet<String>)> = vec![(start, start_features)];
    while let Some((at, requested)) = work.pop() {
        let package = &packages[at];
        if !package.path {
            if seen_registry.insert(at) {
                for dep in &package.dependencies {
                    for to in lock_targets(&packages, dep) {
                        // A registry crate reaching a path package is a `[patch]`: what it
                        // asks of it is unknown here, so it gets its default features.
                        work.push((to, BTreeSet::from(["default".to_string()])));
                    }
                }
            }
            continue;
        }
        let Some(manifest) = members.get(&package.name) else {
            return Err(format!("no manifest found for member {}", package.name));
        };
        let first = !member_features.contains_key(&at);
        let known = member_features.entry(at).or_default();
        let before = known.len();
        known.extend(closure(manifest, &requested));
        if !first && known.len() == before {
            continue;
        }
        let features = known.clone();
        for dep in normal_dependencies(manifest, &workspace_deps) {
            if dep.optional && !turns_on(&features, &dep.key) {
                continue;
            }
            let mut asked: BTreeSet<String> = dep.features.iter().cloned().collect();
            if dep.default_features {
                asked.insert("default".to_string());
            }
            for feature in &features {
                if let Some((key, wanted)) = feature.split_once('/') {
                    if key.trim_end_matches('?') == dep.key {
                        asked.insert(wanted.to_string());
                    }
                }
            }
            let targets: Vec<usize> = package
                .dependencies
                .iter()
                .flat_map(|d| lock_targets(&packages, d))
                .filter(|&to| packages[to].name == dep.package)
                .collect();
            for to in targets {
                work.push((to, asked.clone()));
            }
        }
    }

    Ok(member_features
        .keys()
        .chain(seen_registry.iter())
        .filter(|&&at| at != start)
        .map(|&at| &packages[at])
        .filter(|p| p.name.starts_with("ikigai-"))
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect())
}

fn read_toml(path: &Path) -> Result<toml::Table, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Every workspace member's manifest by package name: the root's own package, and each
/// `[workspace] members` entry (a directory, or a `dir/*` glob, which is all this workspace
/// uses). A packaged crate has no `[workspace]`, so it is its own only member.
fn member_manifests(root: &Path) -> Result<BTreeMap<String, toml::Table>, String> {
    let root_manifest = read_toml(&root.join("Cargo.toml"))?;
    let mut dirs = vec![root.to_path_buf()];
    let globs = root_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for glob in globs.iter().filter_map(toml::Value::as_str) {
        match glob.strip_suffix("/*") {
            Some(parent) => {
                let parent = root.join(parent);
                let entries = std::fs::read_dir(&parent)
                    .map_err(|e| format!("cannot list {}: {e}", parent.display()))?;
                dirs.extend(entries.filter_map(|e| e.ok()).map(|e| e.path()));
            }
            None => dirs.push(root.join(glob)),
        }
    }
    let mut members = BTreeMap::new();
    for dir in dirs {
        let path = dir.join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let manifest = read_toml(&path)?;
        let Some(name) = manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        println!("cargo:rerun-if-changed={}", path.display());
        members.insert(name.to_string(), manifest);
    }
    Ok(members)
}

/// The features Cargo enabled for THIS package, read back from its `CARGO_FEATURE_*`
/// variables (upper-cased, `-` as `_`) against the names its manifest declares.
fn enabled_features(manifest: Option<&toml::Table>) -> BTreeSet<String> {
    let declared = manifest
        .and_then(|m| m.get("features"))
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut on: BTreeSet<String> = declared
        .into_iter()
        .filter(|name| {
            let var = format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"));
            std::env::var_os(var).is_some()
        })
        .collect();
    // An optional dependency is also a feature of its own name; its variable is set too.
    if let Some(manifest) = manifest {
        for dep in normal_dependencies(manifest, &toml::Table::new()) {
            let var = format!("CARGO_FEATURE_{}", dep.key.to_uppercase().replace('-', "_"));
            if dep.optional && std::env::var_os(var).is_some() {
                on.insert(dep.key);
            }
        }
    }
    on
}

/// `requested` expanded through the manifest's `[features]` table: a feature brings in what
/// it lists, recursively. `default` is a feature like any other here; asking for it is how a
/// dependency declared without `default-features = false` arrives.
fn closure(manifest: &toml::Table, requested: &BTreeSet<String>) -> BTreeSet<String> {
    let table = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let mut on = BTreeSet::new();
    let mut work: Vec<String> = requested.iter().cloned().collect();
    while let Some(feature) = work.pop() {
        if !on.insert(feature.clone()) {
            continue;
        }
        if let Some(listed) = table.get(&feature).and_then(toml::Value::as_array) {
            work.extend(listed.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    on
}

/// Whether an enabled feature set turns on the optional dependency keyed `key`: by its own
/// implicit feature (`key`), by `dep:key`, or by `key/feature` (not the weak `key?/feature`,
/// which enables a feature only of a dependency something else turned on).
fn turns_on(features: &BTreeSet<String>, key: &str) -> bool {
    features.iter().any(|f| {
        f == key
            || f.strip_prefix("dep:") == Some(key)
            || f.split_once('/').is_some_and(|(k, _)| k == key)
    })
}

/// One `[dependencies]` entry, as far as linking cares.
struct Dependency {
    /// The key it is declared under (the name a feature uses for it).
    key: String,
    /// The package it names (`package = "…"` renames).
    package: String,
    optional: bool,
    default_features: bool,
    features: Vec<String>,
}

/// The NORMAL dependencies a manifest declares, target-specific ones included (see the module
/// note), each resolved through `[workspace.dependencies]` when it says `workspace = true`.
fn normal_dependencies(manifest: &toml::Table, workspace: &toml::Table) -> Vec<Dependency> {
    let mut tables: Vec<&toml::Table> = Vec::new();
    if let Some(t) = manifest.get("dependencies").and_then(toml::Value::as_table) {
        tables.push(t);
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            if let Some(t) = target.get("dependencies").and_then(toml::Value::as_table) {
                tables.push(t);
            }
        }
    }
    let mut deps = Vec::new();
    for table in tables {
        for (key, value) in table {
            let own = value.as_table();
            let inherited = own
                .filter(|t| t.get("workspace").and_then(toml::Value::as_bool) == Some(true))
                .and_then(|_| workspace.get(key))
                .and_then(toml::Value::as_table);
            let field = |name: &str| {
                own.and_then(|t| t.get(name))
                    .or_else(|| inherited.and_then(|t| t.get(name)))
            };
            let flag = |names: [&str; 2], default: bool| {
                names
                    .iter()
                    .find_map(|n| field(n).and_then(toml::Value::as_bool))
                    .unwrap_or(default)
            };
            let mut features: Vec<String> = Vec::new();
            for t in [own, inherited].into_iter().flatten() {
                if let Some(list) = t.get("features").and_then(toml::Value::as_array) {
                    features.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
                }
            }
            deps.push(Dependency {
                key: key.clone(),
                package: field("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(key)
                    .to_string(),
                optional: own
                    .and_then(|t| t.get("optional"))
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false),
                default_features: flag(["default-features", "default_features"], true),
                features,
            });
        }
    }
    deps
}

/// The lock packages a `dependencies` entry names: `name`, `name version`, or
/// `name version (source)`.
fn lock_targets(packages: &[Locked], entry: &str) -> Vec<usize> {
    let mut words = entry.split(' ');
    let name = words.next().unwrap_or("");
    let version = words.next();
    packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.name == name && version.is_none_or(|v| p.version == v))
        .map(|(at, _)| at)
        .collect()
}
