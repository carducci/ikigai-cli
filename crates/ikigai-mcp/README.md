# ikigai-mcp

Project the capability-scoped ikigai manifold as an **MCP** (Model Context
Protocol) server. An MCP client — Claude Desktop, Claude Code, any host — sees
ikigai's resources as tools, scoped to a capability *grant*.

## Why it's mostly translation, not construction

MCP asks a server for three things, and ikigai already has all three:

| MCP needs | ikigai provides |
|-----------|-----------------|
| a tool list | `urn:kernel:actions` — the capability-scoped action manifold |
| a typed input schema per tool | `ArgSpec` contracts (`one_of` → enum, `class` → type, `default`, `required`) |
| a way to call a tool safely | validate the arguments, then invoke through the kernel |

So this crate is a thin, runtime-free translator (newline-framed JSON-RPC over
stdio — no tokio): each `ik:Action` becomes a tool, the tool name reverses to the
`(endpoint, verb)` it came from, and a `tools/call` validates and invokes.

## Run it

```bash
ikigai mcp --grant <name>        # serve under a named grant (the ceiling)
ikigai mcp --scope urn:cap:…     # …or an ad-hoc scope union
ikigai mcp                       # no grant → root (unrestricted; warns)
ikigai mcp … --show urn:layer:   # list only the tools bound under an IRI prefix (repeatable)
```

`--show <pattern>` narrows the LIST, never the authority. A pattern is a tool name
(`grep__source`), a bare endpoint id (`grep`, every verb), a trailing-`*` prefix
(`repo-*`), or, with a `:` in it, an **IRI prefix** matched against where a tool is bound
rather than its name. The same patterns go in a grant's `"show"` / `"hide"` lists in
`grants.json` (the object form, `{"scopes": […], "show": […], "hide": […]}`), and `--show`
unions with them. An IRI prefix lets an MCP entry for a mounted peer leave the local
kernel's own tools out:

```bash
ikigai mcp --scope urn:cap:layer:read:talk \
  --override urn:layer:,urn:layers:,urn:collab:=quic://door.example:4434 --cert-dir ~/certs/me \
  --show urn:layer: --show urn:layers: --show urn:collab:
```

Wire it into an MCP host, e.g. Claude Desktop's `claude_desktop_config.json`:

```json
{ "mcpServers": {
    "ikigai": { "command": "ikigai", "args": ["mcp", "--grant", "booking-agent"] }
} }
```

## Grants — capability as a named union

A **grant** is a named union of capability scopes, in
`~/.config/ikigai/grants.json` (or `$IKIGAI_GRANTS`):

```json
{ "booking-agent": ["urn:cap:personal:calendar:read:freebusy"],
  "research-agent": ["urn:cap:net:query.wikidata.org", "urn:cap:fs:read:*"] }
```

The grant is the **ceiling**. Because the manifold gates each action
independently, a union grant yields a union of affordances *across features* —
"read the calendar's free/busy **and** hit this host," with the calendar's write
and detail actions simply absent from the tool list. Affordance equals
authorization: an attenuated client can't see, let alone call, what its grant
forbids.

## What the server does

- **`tools/list`** — `select_actions` under the grant → `describe` each →
  project. The manifold *is* the tool list. A tool is one id, verb and
  **contract**: an endpoint served at several doors with one contract is one tool
  (the doors become a selector argument where they align), while a mounted copy
  whose contract differs (another capability, another input) is its own tool,
  `{id}-{first 8 hex of its contract digest}__{verb}`, beside the plain
  `{id}__{verb}` the first contract keeps.
- **`tools/call`** — reverse the name to `(endpoint, verb)`, route Binding
  inputs into the IRI and Argument inputs as request args, **validate** the JSON
  arguments against the typed contract (a non-conforming call returns a SHACL
  report the model repairs from — never a protocol error), then invoke. A
  Binding value is substituted as given (a file path keeps its `/`, an IRI its
  `:`), but a call must reach the tool's OWN endpoint: a value that turns the
  target into another endpoint's IRI (`alice:private` under `urn:x:user:{name}`,
  when `urn:x:user:alice:private` is bound elsewhere) is refused naming the
  argument (0.1.62+; before, the other endpoint answered).
- **Protocol errors per JSON-RPC 2.0 §5.1** — a line that is not JSON gets
  `-32700 Parse error` under `"id": null`; JSON that is not a valid Request (no
  `"jsonrpc": "2.0"`, no `method`, an `id` that is not a string, number or null, a
  scalar, or any array: batching is not part of MCP 2024-11-05, the revision this
  server implements) gets `-32600 Invalid Request`, under the request's `id` when it
  is readable. The reason rides in `error.data`. A notification, or a client's own
  response (a `result` or an `error` with no `method`), is never answered.
- **Concurrent calls** (0.1.64+) — each `tools/call` runs on its own thread and
  is answered when it finishes, so one long call (a feed's `wait=50`) holds no
  other tool up; responses to calls come back in the order they finish, matched
  by `id`. Everything else is answered in arrival order before the next line is
  read. At most `MAX_CONCURRENT_CALLS` (16) run at once: past it a call is
  refused at once with `-32000 Server busy` under its own `id`, the bound in
  `error.data`, never queued. A call runs under the grant in force when its line
  was read. At end of input the server still answers every running call.
- **Live grant-swap** — the server watches the grants file; edit the active
  grant and it emits `notifications/tools/list_changed`, so a connected client's
  tool list morphs with no restart. (Broadening is safe here: it is the human
  editing the grant — root re-granting — never the client escalating itself.)

## Try it without a client

`../../demos/mcp-handshake.sh` drives a scripted JSON-RPC session (handshake,
capability-scoped `tools/list`, and a couple of `tools/call`s), and
`../../demos/grants.json.example` documents the grant shape.

## Boundary

The grant is a **policy** boundary enforced kernel-side: a compromised or
prompt-injected *model* cannot exceed it. It is **not** a defense against an
attacker who can already edit the config files — that threat is answered by
identity-bound grants (mTLS / passkey / OAuth) and signed config, not by MCP.

## License
MIT OR Apache-2.0. See `../../LICENSE-MIT` / `../../LICENSE-APACHE`.
