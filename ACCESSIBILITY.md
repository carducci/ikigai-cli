# Accessibility

What `ikigai-cli` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA for the HTML this repository writes |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-cli/issues/new); anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-cli/security/advisories/new) |
| Last reviewed | 2026-10-15 |

## What it emits that people read

- **Error pages** from the HTTP door (`crates/ikigai-web/src/error_page.rs`): a refusal, as a page,
  for a client that names `text/html` over `text/plain` (a browser); every other client gets the
  same sentence as text.
- **Pages from the embedded host's HTTP face**: the emailed decision, contact-block and label
  links and the passkey enrollment page (`crates/ikigai-embedded`: `decide.rs`, `contactblock.rs`,
  `passkey.rs`, all through `decide::page`), and the contact intake's redirect page
  (`crates/ikigai-intake`).
- **Terminal text**: the full-screen REPL (`tui.rs`, the default on an interactive terminal), the
  line REPL (`--plain`, or when stdin is not a terminal), `-c` batches, `--quiet` output, usage
  text and error lines.
- **Pictures**: `show <iri>` writes an SVG another crate drew (for example `urn:diagram:kernel`,
  from `ikigai-diagram`) to a file and opens it. The picture's accessibility is that crate's.

Not this repository's: markup an endpoint or a workspace stylesheet produces behind a route (for
example `urn:iki:foaf`'s HTML face, from the operator's `urn:file:foaf.xsl`).

## The rules that output follows

- An error page has `<html lang="en">`, a `<title>` and one `<h1>` naming the status, a `<main>`,
  and the message as escaped text; no style, no script. Its status code is the same as the text
  answer's, and both carry `Vary: Accept`.
- Nothing is said by color alone. An evaluation error in either REPL starts with the word
  `error:` and the binary's own failures with `ikigai:`, a cache verdict is a word (`cached`,
  `computed`, `uncacheable`), and the full-screen REPL's colors (cyan prompt,
  green output, red error) repeat what the text already says.
- `--plain` is a line-oriented REPL with no full-screen redraw, so a screen reader or braille
  display reads it as ordinary terminal output; `--quiet` prints only the answers. (Not yet tested
  with either; see below.)

## How it is tested

- `crates/ikigai-web/tests/error_pages.rs` (7 tests) and the unit tests in `error_page.rs` pin the
  page's shape (`lang`, title, `main`, `h1`), escaping, which clients get a page, `Vary: Accept`,
  and that a JSON door and a success are left alone.
- The full-screen REPL is rendered against ratatui's test backend in `tui.rs`'s tests: layout and
  editing, not accessibility.
- No automated accessibility checker (axe or similar), no browser run and no assistive technology
  has been used on any of this output.

## Known limitations

Found by reading the source on 2026-10-15, not by testing:

- `decide::page` (the decision, contact-block, label and passkey pages) writes no `<html lang>`
  (SC 3.1.1 Language of Page) and no `<main>` landmark.
- The passkey pages' status line (`#status`, `#pkstatus`) is not a live region, so a screen reader
  is not told when the ceremony succeeds or fails (SC 4.1.3 Status Messages).
- The full-screen REPL redraws the whole terminal and does not read `NO_COLOR`; use `--plain`.
- Nothing above has been tried with a screen reader, magnifier or braille display.

## Contributing

Read this file before changing any output listed above. A change to an HTML page keeps the rules
above and adds a test that pins them; a change to terminal output keeps meaning in words. Say in
the pull request what was tested, with what, and what was not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-cli/issues/new) with "accessibility" in its
title: what you were doing, what happened, and your terminal or browser and any assistive
technology, if you are comfortable sharing them. Anything security-sensitive goes through
[private vulnerability reporting](https://github.com/ikigai-rs/ikigai-cli/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.
