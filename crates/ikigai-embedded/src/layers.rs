//! The layer host a served QUIC door links (`ikigai-layers`, ledger #1188).
//!
//! **The switch is a directory.** When the config home holds `layers/`, `serve quic://` opens
//! an [`ikigai_layers::Host`] over the config home (the layer definitions under `layers/`,
//! `participants.ttl`, `collabs/*.toml`) and a STATE directory, and binds
//! [`ikigai_layers::space`] beside [`ikigai_shacl::space`] on a kernel with a clock. Without
//! `layers/` nothing here runs, and the served kernel is built exactly as before.
//!
//! **Where the state lives** — config home for the setting, data home for the bytes, and no
//! environment variable names either (the store's rule, `store.rs`):
//!
//! 1. `--layers-state <dir>` on `serve` ([`StateSource::Flag`]), relative to the working
//!    directory;
//! 2. `<instance>.layers.state` in the config home's `config.toml`, else `layers.state`
//!    ([`StateSource::Config`]), relative to the config home;
//! 3. `<data home>/layers/<instance>`, i.e. `~/.ikigai/layers/<instance>`
//!    ([`StateSource::Default`]).
//!
//! The default is per INSTANCE because a layer host is one process per state directory (the
//! lock that keeps a feed gapless is in-process): two doors with different `--name`s reading
//! one config home must not write one state directory.
//!
//! **Admission fails closed, so the host refuses to start without a validator.** `say` and
//! `out` admit an entry only when `urn:shacl:validate` answers `conforms: true`; a host whose
//! validator does not resolve would serve layers that admit nothing. [`check_validator`] runs
//! one validation through the built kernel, the way admission will, and the door refuses to
//! start when it fails.
//!
//! **Who writes is the door's business.** Participants are the config home's `clients.json` /
//! `grants.json`, as `ikigai-layers grants <config home>` generates them: each certificate's
//! entry names its grant (`urn:cap:layer:{verb}:{layer}` scopes) and its `principal` (the
//! participant's IRI), which the door mints into the connection's capability exactly as it
//! does for every other client ([`crate::clients`]). Nothing here reads either file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ikigai_core::{
    ArgRef, Capability, EndpointSpace, Iri, Kernel, Request, Space, SystemClock, Verb,
};

/// The directory under the config home whose presence switches the layer host on.
pub const DIR: &str = "layers";

/// The config-home key naming the state directory, instance-scoped as
/// `<instance>.layers.state`. A relative path is resolved against the config home; `~/`
/// against `$HOME`.
pub const STATE_KEY: &str = "layers.state";

/// The flag naming the state directory, on `serve quic://`.
pub const STATE_FLAG: &str = "--layers-state";

/// The name the served root gives the layer space: the space answers what its host was
/// handed, so it claims no name of its own and the host names it (core's `SPACE-NAME` rule).
pub const SPACE: &str = "urn:ikigai:space:served:layers";

/// The validator admission composes.
pub const VALIDATE: &str = ikigai_layers::endpoints::VALIDATE;

/// Which channel named the state directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateSource {
    /// `--layers-state <dir>`.
    Flag,
    /// `layers.state` (or `<instance>.layers.state`) in the config home.
    Config,
    /// Neither: `<data home>/layers/<instance>`.
    Default,
}

impl StateSource {
    /// `flag` / `config` / `default`, as the banner says it.
    pub fn as_str(self) -> &'static str {
        match self {
            StateSource::Flag => "flag",
            StateSource::Config => "config",
            StateSource::Default => "default",
        }
    }
}

/// An opened layer host and where it came from.
pub struct Hosted {
    /// The host [`ikigai_layers::space`] binds.
    pub host: Arc<ikigai_layers::Host>,
    /// The config home it was opened over (its `layers/` holds the definitions).
    pub config: PathBuf,
    /// The state directory it writes.
    pub state: PathBuf,
    /// Which channel named [`state`](Self::state).
    pub source: StateSource,
}

impl Hosted {
    /// One banner line per layer: `talk (channel)`, `tasks-bobby (tuplespace)`.
    pub fn layer_lines(&self) -> Vec<String> {
        self.host
            .layers()
            .iter()
            .map(|(name, state)| format!("{name} ({})", state.def.model.as_str()))
            .collect()
    }
}

/// `<config home>/layers/` when it is a directory: the switch.
pub fn configured() -> Option<PathBuf> {
    configured_in(&crate::config::config_home()?)
}

/// [`configured`] for an explicit config home.
pub fn configured_in(home: &Path) -> Option<PathBuf> {
    let dir = home.join(DIR);
    dir.is_dir().then_some(dir)
}

/// Where the state lives, by the precedence in the module docs. `flag` is `--layers-state`,
/// already absolute (the binary absolutizes what was typed).
pub fn state_dir(flag: Option<&Path>) -> Result<(PathBuf, StateSource), String> {
    let instance = crate::instance_name();
    let configured = crate::config::get(&format!("{instance}.{STATE_KEY}"))
        .or_else(|| crate::config::get(STATE_KEY));
    state_dir_from(
        flag,
        configured.as_deref(),
        crate::config::config_home().as_deref(),
        std::env::var_os("HOME").as_deref().map(Path::new),
        instance,
    )
}

/// [`state_dir`] with every input passed in, so the precedence is testable without touching
/// the process environment.
pub fn state_dir_from(
    flag: Option<&Path>,
    configured: Option<&str>,
    config_home: Option<&Path>,
    home: Option<&Path>,
    instance: &str,
) -> Result<(PathBuf, StateSource), String> {
    if let Some(dir) = flag {
        return Ok((dir.to_path_buf(), StateSource::Flag));
    }
    if let Some(value) = configured.map(str::trim).filter(|v| !v.is_empty()) {
        let path = match (value.strip_prefix("~/"), home) {
            (Some(rest), Some(home)) => home.join(rest),
            _ => PathBuf::from(value),
        };
        let path = match config_home {
            Some(base) if path.is_relative() => base.join(path),
            _ => path,
        };
        return Ok((path, StateSource::Config));
    }
    let home = home.filter(|h| !h.as_os_str().is_empty()).ok_or_else(|| {
        format!(
            "layers are configured but no state directory is: pass {STATE_FLAG} <dir>, set \
             `{STATE_KEY}` in the config home, or set HOME so the default \
             (~/.ikigai/layers/{instance}) has somewhere to be"
        )
    })?;
    Ok((
        ikigai_core::config::data_home_in(home)
            .join("layers")
            .join(instance),
        StateSource::Default,
    ))
}

/// Open the layer host when the config home configures one: `Ok(None)` without `layers/`
/// (and then `flag` must be `None`: a state directory for layers nobody configured is a
/// flag that does nothing, and is refused rather than ignored).
pub fn open(flag: Option<&Path>) -> Result<Option<Hosted>, String> {
    let Some(home) = crate::config::config_home() else {
        return match flag {
            Some(_) => Err(format!("{STATE_FLAG} needs a config home holding `{DIR}/`")),
            None => Ok(None),
        };
    };
    if configured_in(&home).is_none() {
        return match flag {
            Some(_) => Err(format!(
                "{STATE_FLAG} names where layers keep their state, but {} does not exist, so \
                 no layer is configured",
                home.join(DIR).display()
            )),
            None => Ok(None),
        };
    }
    let (state, source) = state_dir(flag)?;
    let host = ikigai_layers::Host::open(&home, &state).map_err(|e| {
        format!(
            "layers are configured in {} but the host cannot open: {e}",
            home.join(DIR).display()
        )
    })?;
    Ok(Some(Hosted {
        host,
        config: home,
        state,
        source,
    }))
}

/// The spaces a hosting kernel binds, in order: the layers, then the validator their
/// admission composes.
pub fn spaces(host: &Arc<ikigai_layers::Host>) -> Vec<Arc<dyn Space>> {
    let layers: EndpointSpace = ikigai_layers::space(host)
        .named(Iri::parse(SPACE).expect("the layer space's name is an IRI"));
    vec![
        Arc::new(layers) as Arc<dyn Space>,
        Arc::new(ikigai_shacl::space()) as Arc<dyn Space>,
    ]
}

/// The clock a hosting kernel carries: every entry, tuple and receipt is stamped with the
/// kernel's time, and a layer refuses a write when it has none.
pub fn clock() -> Arc<dyn ikigai_core::Clock> {
    Arc::new(SystemClock)
}

/// Prove the built kernel can admit: one validation through it, issued the way admission
/// issues it (inline shapes and data, a JSON report, an EMPTY capability), must answer
/// `conforms: true`. Anything else — the validator unresolved, refused, or answering
/// something that is not a report — is the reason the door refuses to start.
pub fn check_validator(kernel: &Kernel) -> Result<(), String> {
    const SHAPES: &str = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n\
        <urn:ikigai:layers:probe:shape> a sh:NodeShape ;\n  \
        sh:targetClass <urn:ikigai:layers:probe:Thing> .\n";
    const DATA: &str = "<urn:ikigai:layers:probe:thing> a <urn:ikigai:layers:probe:Thing> .\n";
    let refuse = |why: String| {
        format!(
            "layers are configured, but admission cannot run on this kernel: {why}. Every \
             write to a layer composes {VALIDATE}, and a layer without it admits nothing, so \
             this door does not start"
        )
    };
    let request = Request::new(Verb::Source, Iri::parse(VALIDATE).expect("a constant IRI"))
        .with_arg("data", ArgRef::Inline(DATA.as_bytes().to_vec()))
        .with_arg("shapes", ArgRef::Inline(SHAPES.as_bytes().to_vec()))
        .with_arg("as", ArgRef::Inline(b"application/json".to_vec()));
    let (report, _) = ikigai_resolve::Resolver::issue_as(
        kernel,
        request,
        &Capability::scoped(Vec::<String>::new()),
    )
    .map_err(|e| refuse(format!("{VALIDATE} failed ({e})")))?;
    let report: serde_json::Value = serde_json::from_slice(&report.bytes).map_err(|e| {
        refuse(format!(
            "{VALIDATE} answered something that is not a report ({e})"
        ))
    })?;
    match report.get("conforms").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(()),
        other => Err(refuse(format!(
            "{VALIDATE} judged a conforming probe {}",
            match other {
                Some(false) => "NOT conforming".to_string(),
                _ => "without a `conforms`".to_string(),
            }
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikigai_core::Fallback;

    #[test]
    fn the_flag_wins_then_the_config_home_then_the_data_home() {
        let flag = Path::new("/srv/flagged");
        let home = Path::new("/home/b");
        let config = Path::new("/home/b/.config/ikigai");
        assert_eq!(
            state_dir_from(
                Some(flag),
                Some("ignored"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((flag.to_path_buf(), StateSource::Flag))
        );
        // Relative to the config home, `~/` to HOME, absolute as written.
        assert_eq!(
            state_dir_from(None, Some("state"), Some(config), Some(home), "layers"),
            Ok((config.join("state"), StateSource::Config))
        );
        assert_eq!(
            state_dir_from(
                None,
                Some("~/layer-state"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((home.join("layer-state"), StateSource::Config))
        );
        assert_eq!(
            state_dir_from(
                None,
                Some("/var/layers"),
                Some(config),
                Some(home),
                "layers"
            ),
            Ok((PathBuf::from("/var/layers"), StateSource::Config))
        );
        // The default is per instance, under the data home.
        assert_eq!(
            state_dir_from(None, None, Some(config), Some(home), "layers"),
            Ok((home.join(".ikigai/layers/layers"), StateSource::Default))
        );
        assert_eq!(
            state_dir_from(None, Some("  "), Some(config), Some(home), "edge"),
            Ok((home.join(".ikigai/layers/edge"), StateSource::Default)),
            "a blank setting is no setting"
        );
        let err = state_dir_from(None, None, Some(config), None, "layers").unwrap_err();
        assert!(err.contains(STATE_FLAG) && err.contains(STATE_KEY), "{err}");
    }

    #[test]
    fn only_a_directory_switches_the_host_on() {
        let dir = std::env::temp_dir().join(format!("iki-layers-switch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(configured_in(&dir), None);
        std::fs::write(dir.join(DIR), "not a directory").unwrap();
        assert_eq!(
            configured_in(&dir),
            None,
            "a FILE named layers is not a configuration"
        );
        std::fs::remove_file(dir.join(DIR)).unwrap();
        std::fs::create_dir(dir.join(DIR)).unwrap();
        assert_eq!(configured_in(&dir), Some(dir.join(DIR)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The refusal the door turns on: a kernel without the validator cannot admit, and the
    /// check names what is missing; with it bound, the probe conforms.
    #[test]
    fn a_kernel_without_the_validator_fails_the_check_and_one_with_it_passes() {
        let bare = Kernel::new(Arc::new(EndpointSpace::new()));
        let err = check_validator(&bare).unwrap_err();
        assert!(err.contains(VALIDATE), "names the validator: {err}");
        assert!(err.contains("does not start"), "says what follows: {err}");

        let with: Kernel = Kernel::new(Arc::new(Fallback::new(vec![
            Arc::new(ikigai_shacl::space()) as Arc<dyn Space>,
        ])));
        check_validator(&with).expect("the real validator admits the probe");
    }
}
