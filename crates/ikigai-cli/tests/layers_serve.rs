//! `serve quic://` hosts LAYERS when the config home has a `layers/` directory (ledger #1188),
//! through the REAL binary and the real QUIC door, with two enrolled client certificates.
//!
//! The enrollment is the one `ikigai-layers grants <config dir>` writes: this suite calls the
//! same generator (`ikigai_layers::grants`) over the same configuration, so what is proved is
//! that the door serves the files the layer host's own tool produces. Each certificate's
//! entry names its participant as `principal`, the door mints it into the connection's
//! capability (ledger #1179), and the layer stamps it into every write.
//!
//! ★ Every door binds port 0 and the test reads the bound port off its banner. Picking a port
//! by binding one and releasing it races a child another test thread spawns, which can
//! inherit the socket on macOS and hold the port (field guide 9h, ledger #1223).
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `quic_principals.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

const ALICE: &str = "urn:collab:participant:alice";
const BOB: &str = "urn:collab:participant:bob";

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home unique to this case and process, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-ls-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config_home(&dir)).expect("scratch config home");
    dir
}

fn config_home(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        // The test harness may run with the developer's own overrides set; these would
        // point the child at real enrolment files.
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    spawn(home, args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs")
}

fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A certificate set: the server pair, the base client, and `alice` and `bob`.
fn certs(home: &Path) -> PathBuf {
    let dir = home.join("certs");
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in ["alice", "bob"] {
        ok(
            run(home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    dir
}

/// The fingerprint a door keys a client by: lowercase hex SHA-256 of its certificate DER.
fn fingerprint(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).expect("the client certificate");
    ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate")
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The closed shapes every write is admitted against: a message, an offer, each allowing
/// the three stamps the host adds.
const SHAPES: &str = r#"@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ik: <https://ikigai-rs.dev/ns#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

<urn:example:shape:message> a sh:NodeShape ;
  sh:targetClass ik:Message ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path ik:body ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .

<urn:example:shape:offer> a sh:NodeShape ;
  sh:targetClass ik:Offer ;
  sh:closed true ;
  sh:ignoredProperties ( rdf:type ) ;
  sh:property [ sh:path dcterms:title ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path ik:brief ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:string ] ,
              [ sh:path prov:wasAttributedTo ; sh:minCount 1 ; sh:maxCount 1 ; sh:nodeKind sh:IRI ] ,
              [ sh:path dcterms:created ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:dateTime ] ,
              [ sh:path ik:seq ; sh:minCount 1 ; sh:maxCount 1 ; sh:datatype xsd:integer ] .
"#;

const CONTEXT: &str = r#"{ "@context": {
  "ik": "https://ikigai-rs.dev/ns#",
  "dcterms": "http://purl.org/dc/terms/",
  "Message": "ik:Message", "Offer": "ik:Offer",
  "body": "ik:body", "title": "dcterms:title", "brief": "ik:brief"
} }
"#;

/// The configuration, in the config home: three layers in two collaborations.
///
/// - `talk` (a channel) and `tasks` (an addressed tuplespace), mounted by `pair`: alice and
///   bob both read, follow, say, drop and take;
/// - `side` (a channel), mounted by `solo`: alice alone. Bob is in no collaboration that
///   mounts it, so nothing of it may reach his manifold.
///
/// Then the enrollment, generated by the layer host's own generator into the config home.
fn configure_layers(home: &Path, certs: &Path) {
    let config = config_home(home);
    write(config.join("layers/shapes.ttl"), SHAPES);
    write(config.join("layers/context.jsonld"), CONTEXT);
    let channel = "model = \"channel\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\n";
    write(config.join("layers/talk.toml"), channel);
    write(config.join("layers/side.toml"), channel);
    write(
        config.join("layers/tasks.toml"),
        "model = \"tuplespace\"\nshapes = \"shapes.ttl\"\ncontext = \"context.jsonld\"\naddressed = true\n",
    );
    write(
        config.join("participants.ttl"),
        &format!(
            "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<{ALICE}> a foaf:Person .\n<{BOB}> a foaf:Person .\n"
        ),
    );
    write(
        config.join("collabs/pair.toml"),
        "[[mount]]\nlayer = \"talk\"\nalice = [\"read\", \"feed\", \"say\"]\nbob = [\"read\", \"feed\", \"say\"]\n\n\
         [[mount]]\nlayer = \"tasks\"\nalice = [\"read\", \"feed\", \"out\", \"take\"]\nbob = [\"read\", \"feed\", \"out\", \"take\"]\n",
    );
    write(
        config.join("collabs/solo.toml"),
        "[[mount]]\nlayer = \"side\"\nalice = [\"read\", \"feed\", \"say\"]\n",
    );
    write(
        config.join("enrollment.toml"),
        &format!(
            "alice = \"{}\"\nbob = \"{}\"\n",
            fingerprint(&certs.join("clients/alice.crt")),
            fingerprint(&certs.join("clients/bob.crt"))
        ),
    );
    // `ikigai-layers grants <config home>`, as a library call.
    let loaded = ikigai_layers::Config::load(&config).expect("the configuration checks");
    let fingerprints: BTreeMap<String, BTreeSet<String>> =
        ikigai_layers::grants::load_fingerprints(&config, &loaded).expect("enrollment.toml");
    let enrollment =
        ikigai_layers::grants::generate(&loaded, &fingerprints).expect("an enrollment");
    assert_eq!(enrollment.clients.len(), 2, "both certificates enrolled");
    enrollment
        .write(&config)
        .expect("grants.json and clients.json");
}

/// Start `serve quic://127.0.0.1:0 --name layers` with `extra` flags. Returns the door, the
/// address its banner names (the BOUND port) and its stderr up to the banner.
fn serve(home: &Path, certs: &Path, extra: &[&str]) -> (Door, String, String) {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let mut child = spawn(home, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    // Keep draining after the banner, so the door's log is a pipe someone reads.
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never printed its banner: {e}"));
    let target = seen
        .lines()
        .find_map(|line| line.split("serving on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address in the banner:\n{seen}"))
        .to_string();
    assert!(
        !target.ends_with(":0"),
        "the banner names the BOUND port, not the one asked for: {target}"
    );
    (door, target, seen)
}

/// Ask the door `command` as `who` (`alice` or `bob`), writing `stdin` to the client when
/// given (the value a content-less `sink` reads).
fn ask(
    home: &Path,
    certs: &Path,
    who: &str,
    target: &str,
    command: &str,
    stdin: Option<&str>,
) -> Output {
    let dir = certs.to_str().unwrap();
    let cert = format!("{dir}/clients/{who}.crt");
    let key = format!("{dir}/clients/{who}.key");
    let mut child = spawn(
        home,
        &[
            "--cert-dir",
            dir,
            "--client-cert",
            &cert,
            "--client-key",
            &key,
            "--connect",
            target,
            "--plain",
            "-c",
            command,
        ],
    )
    .stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("the client starts");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
        // Dropped here: EOF, so the client reads the whole value.
    }
    child.wait_with_output().expect("the client ran")
}

/// The first line of a successful answer: an IRI a write answered with.
fn first_line(out: Output, what: &str) -> String {
    ok(out, what)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

const IK: &str = "https://ikigai-rs.dev/ns#";

fn message(body: &str) -> String {
    format!("@prefix ik: <{IK}> .\n<urn:layer:new> a ik:Message ; ik:body \"{body}\" .\n")
}

/// A message in a channel layer is attributed to EACH sender's principal — the one the door
/// minted from that sender's certificate — and a sender that sends any of the three stamps
/// (attribution, time, sequence) is refused, so none can be forged.
#[test]
fn a_message_in_a_channel_layer_is_attributed_to_each_sender_and_a_sent_stamp_is_refused() {
    let home = scratch("chan");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let state = home.join("layer-state");
    let (_door, target, banner) =
        serve(&home, &certs, &["--layers-state", state.to_str().unwrap()]);
    assert!(
        banner.contains("layers: side (channel), talk (channel), tasks (tuplespace)"),
        "the banner names what it hosts: {banner}"
    );
    assert!(
        banner.contains(&format!("state in {} (flag)", state.display())),
        "and where the state lives, by which channel: {banner}"
    );

    let say = |who: &str, body: &str| {
        first_line(
            ask(
                &home,
                &certs,
                who,
                &target,
                "sink urn:layer:talk:say",
                Some(&message(body)),
            ),
            &format!("{who} says"),
        )
    };
    let from_alice = say("alice", "hello from alice");
    let from_bob = say("bob", "hello from bob");
    for (entry, author) in [(&from_alice, ALICE), (&from_bob, BOB)] {
        assert!(
            entry.starts_with("urn:layer:talk:entry:"),
            "an entry IRI: {entry}"
        );
        // Read back by the OTHER participant: what is stored, not what the writer saw.
        let reader = if author == ALICE { "bob" } else { "alice" };
        let stored = ok(
            ask(
                &home,
                &certs,
                reader,
                &target,
                &format!("source {entry}"),
                None,
            ),
            "read an entry",
        );
        assert!(
            stored.contains(&format!("prov:wasAttributedTo <{author}>")),
            "{entry} is attributed to {author}:\n{stored}"
        );
        assert!(stored.contains("dcterms:created") && stored.contains("ik:seq"));
    }
    let feed = ok(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            "source urn:layer:talk:feed after=0",
            None,
        ),
        "the feed",
    );
    assert!(
        feed.contains(&format!(" say {from_alice} {ALICE}")),
        "{feed}"
    );
    assert!(feed.contains(&format!(" say {from_bob} {BOB}")), "{feed}");

    // Each stamp, sent by a writer, is refused, and nothing is stored or logged.
    for (prefix, stamp) in [
        (
            "@prefix prov: <http://www.w3.org/ns/prov#> .",
            format!("prov:wasAttributedTo <{ALICE}>"),
        ),
        (
            "@prefix dcterms: <http://purl.org/dc/terms/> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
            "dcterms:created \"2026-01-01T00:00:00Z\"^^xsd:dateTime".to_string(),
        ),
        ("", "ik:seq 99".to_string()),
    ] {
        let forged = format!(
            "@prefix ik: <{IK}> .\n{prefix}\n<urn:layer:new> a ik:Message ; ik:body \"forged\" ; {stamp} .\n"
        );
        let out = ask(
            &home,
            &certs,
            "bob",
            &target,
            "sink urn:layer:talk:say",
            Some(&forged),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("stamped by the host"),
            "a sent `{stamp}` is refused: {}{stderr}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    let feed = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:layer:talk:feed after=0",
            None,
        ),
        "the feed again",
    );
    assert_eq!(
        feed.lines().filter(|l| l.contains(" say ")).count(),
        2,
        "no refused write reached the feed: {feed}"
    );
    assert!(
        state.join("talk").join("feed.log").is_file(),
        "the state lives where --layers-state said"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A take in a tuplespace layer names its TAKER — bob, from his certificate — in the feed and
/// in the receipt the host commits before replying; the dropper is named on the `out`; and a
/// second taker is refused with a Conflict that names the first.
#[test]
fn a_take_in_a_tuplespace_layer_names_its_taker_in_the_feed_and_a_receipt() {
    let home = scratch("take");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);

    let offer = "urn:layer:tasks:offer:01m4hhr0z8";
    let dropped = first_line(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "sink urn:layer:tasks:tuples",
            Some(&format!(
                "@prefix ik: <{IK}> .\n@prefix dcterms: <http://purl.org/dc/terms/> .\n\
                 <{offer}> a ik:Offer ; dcterms:title \"Host layers\" ; ik:brief \"Serve them.\" .\n"
            )),
        ),
        "alice drops an offer",
    );
    assert_eq!(dropped, offer, "out answers the tuple's subject");

    let taken = ok(
        ask(
            &home,
            &certs,
            "bob",
            &target,
            &format!("delete urn:layer:tasks:tuples {offer}"),
            None,
        ),
        "bob takes it",
    );
    assert!(
        taken.contains("Host layers"),
        "a take answers the tuple: {taken}"
    );

    let feed = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:layer:tasks:feed after=0",
            None,
        ),
        "the task feed",
    );
    assert!(feed.contains(&format!(" out {offer} {ALICE}")), "{feed}");
    assert!(feed.contains(&format!(" taken {offer} {BOB}")), "{feed}");

    let receipt = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            &format!("source urn:layer:tasks:tuples state=taken tuple={offer}"),
            None,
        ),
        "the receipt",
    );
    assert!(
        receipt.contains(&format!("prov:wasAssociatedWith <{BOB}>")),
        "the receipt names the taker:\n{receipt}"
    );

    let again = ask(
        &home,
        &certs,
        "alice",
        &target,
        &format!("delete urn:layer:tasks:tuples {offer}"),
        None,
    );
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        !again.status.success() && stderr.contains(BOB),
        "a second taker is refused, told who won: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The layer families a manifold names: `talk` from `urn:layer:talk:say`, and so on.
fn layers_in(manifold: &str) -> BTreeSet<String> {
    manifold
        .lines()
        .filter_map(|line| line.trim().strip_prefix("urn:layer:"))
        .map(|rest| rest.split(':').next().unwrap_or(rest).to_string())
        .collect()
}

/// A participant's manifold (`urn:kernel:actions` under the capability its certificate
/// earns) lists exactly its layers' actions: every action of every layer it holds, and
/// nothing of a layer it is not in.
#[test]
fn a_participants_manifold_lists_exactly_its_layers_actions() {
    let home = scratch("mani");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    let (_door, target, _banner) = serve(&home, &certs, &[]);
    let manifold = |who: &str| {
        ok(
            ask(
                &home,
                &certs,
                who,
                &target,
                "source urn:kernel:actions",
                None,
            ),
            &format!("{who}'s manifold"),
        )
    };
    let set = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();

    let bob = manifold("bob");
    assert_eq!(layers_in(&bob), set(&["talk", "tasks"]), "bob:\n{bob}");
    assert!(
        !bob.contains("urn:layer:side"),
        "nothing of side reaches bob:\n{bob}"
    );
    let alice = manifold("alice");
    assert_eq!(
        layers_in(&alice),
        set(&["side", "talk", "tasks"]),
        "alice:\n{alice}"
    );

    // Every action each layer binds, by its model.
    for action in [
        "urn:layer:talk",
        "urn:layer:talk:say",
        "urn:layer:talk:entries",
        "urn:layer:talk:entry:{id}",
        "urn:layer:talk:latest",
        "urn:layer:talk:feed",
        "urn:layer:tasks:tuples",
        "urn:layer:tasks:receipt:{id}",
        "urn:layer:tasks:feed",
        "urn:layers:feed",
    ] {
        assert!(
            bob.lines().any(|line| line.trim() == action),
            "bob holds {action}:\n{bob}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// Whether a catalog endpoint id is one a hosted layer brings: the layer actions
/// (`layer-{layer}-{action}`), the host-wide reads (`layers-feed`, `layers-participants`,
/// `collab`) and the validator admission composes (`shacl-validate`).
fn is_layer_endpoint(id: &str) -> bool {
    id.starts_with("layer-")
        || id.starts_with("layers-")
        || id == "collab"
        || id.starts_with("shacl-")
}

/// With NO `layers/` directory the door is the door it always was: no layer, no validator, no
/// banner line, the same surface, and the same manifold as a door whose config home differs
/// only by `layers/` — minus exactly the layer families.
#[test]
fn without_a_layers_directory_serve_is_unchanged() {
    let home = scratch("none");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    // The catalog is the WHOLE surface (`urn:kernel:actions` is only what a grant reaches),
    // and reading it takes `urn:cap:kernel:inspect`: give alice's generated grant that too.
    let grants_path = config_home(&home).join("grants.json");
    let mut grants: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&grants_path).unwrap()).unwrap();
    grants["alice"]
        .as_array_mut()
        .expect("alice's grant is a list of scopes")
        .push("urn:cap:kernel:inspect".into());
    std::fs::write(&grants_path, grants.to_string()).unwrap();
    let (door, target, banner) = serve(&home, &certs, &[]);
    let with = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:kernel:catalog",
            None,
        ),
        "the catalog with layers",
    );
    drop(door);

    // The same config home without `layers/`: the enrollment stays, so alice is still served.
    std::fs::remove_dir_all(config_home(&home).join("layers")).unwrap();
    let (_door, target, plain) = serve(&home, &certs, &[]);
    assert!(banner.contains("surface: host + fs + layers"), "{banner}");
    assert!(plain.contains("surface: host + fs;"), "{plain}");
    assert!(
        !plain.contains("ikigai: layers:"),
        "no layers line: {plain}"
    );
    let without = ok(
        ask(
            &home,
            &certs,
            "alice",
            &target,
            "source urn:kernel:catalog",
            None,
        ),
        "the catalog without layers",
    );
    // The catalog is Turtle, one `ik:Endpoint` per bound endpoint, each with its `ik:id`.
    let ids = |catalog: &str| -> BTreeSet<String> {
        catalog
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ik:id \""))
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_string)
            .collect()
    };
    let (with, without) = (ids(&with), ids(&without));
    assert!(
        without.contains("host-identity"),
        "the catalog was read: {without:?}"
    );
    for id in &without {
        assert!(
            !is_layer_endpoint(id),
            "no layer endpoint without layers/: {id}"
        );
    }
    let added: Vec<&String> = with.difference(&without).collect();
    assert!(
        added.contains(&&"layer-talk-say".to_string())
            && added.contains(&&"layer-tasks-tuples".to_string())
            && added.contains(&&"shacl-validate".to_string()),
        "hosting layers adds the layers and their validator: {added:?}"
    );
    for id in &added {
        assert!(
            is_layer_endpoint(id),
            "hosting layers adds ONLY layer endpoints, not {id}"
        );
    }
    assert!(
        without.is_subset(&with),
        "and removes nothing: {:?}",
        without.difference(&with).collect::<Vec<_>>()
    );

    // A state directory for a door that hosts no layer is a flag that does nothing: refused.
    let out = run(
        &home,
        &[
            "serve",
            "quic://127.0.0.1:0",
            "--cert-dir",
            certs.to_str().unwrap(),
            "--layers-state",
            home.join("nowhere").to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("--layers-state"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Start `serve quic://127.0.0.1:0 --name layers` with `extra` flags and report how it
/// ENDED: `Ok(banner)` when it printed `serving on` (the door is killed), `Err((code, stderr))`
/// when it exited first.
fn start_or_refuse(home: &Path, certs: &Path, extra: &[&str]) -> Result<String, (i32, String)> {
    let mut args = vec![
        "serve",
        "quic://127.0.0.1:0",
        "--name",
        "layers",
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let mut child = spawn(home, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut served = false;
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                served = true;
                break;
            }
        }
        let _ = tx.send((served, seen));
        lines.for_each(drop);
    });
    let (served, seen) = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` neither served nor exited: {e}"));
    if served {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(seen);
    }
    // stderr reached EOF: the process is exiting. `wait`, never `try_wait` (field guide 9h).
    let status = child.wait().expect("the door's exit status");
    Err((status.code().unwrap_or(-1), seen))
}

/// ledger #1281: a door whose config home has `layers/` but NO `clients.json` used to start in
/// the per-client-workspace posture, where every trusted certificate gets fs read, write and
/// delete in its own segment and no participant has a grant. A door that hosts layers is for
/// participants, so it refuses to start without per-identity grants, under `--cap` too, and
/// says which file is missing. Without `layers/`, the same config home still serves as before.
#[test]
fn a_layer_door_without_per_identity_grants_refuses_to_start() {
    let home = scratch("nogrants");
    let certs = certs(&home);
    configure_layers(&home, &certs);
    std::fs::remove_file(config_home(&home).join("clients.json")).unwrap();

    for extra in [&[][..], &["--cap", "urn:cap:space:read"][..]] {
        let (code, stderr) = start_or_refuse(&home, &certs, extra)
            .expect_err("a layer door with no clients.json must not serve");
        assert_ne!(code, 0, "{extra:?}: a refusal exits non-zero: {stderr}");
        assert!(
            stderr.contains("clients.json") && stderr.contains("grants.json"),
            "{extra:?}: the refusal names the per-identity grants it needs: {stderr}"
        );
        assert!(!stderr.contains("serving on"), "{extra:?}: {stderr}");
    }

    // The same config home without `layers/` is the door it always was.
    std::fs::remove_dir_all(config_home(&home).join("layers")).unwrap();
    let banner = start_or_refuse(&home, &certs, &[]).expect("a door without layers/ serves");
    assert!(banner.contains("per-client workspaces"), "{banner}");
    let _ = std::fs::remove_dir_all(&home);
}
