[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![rust version][rust-version-badge]][rust-version-url]
[![Build Status][actions-badge]][actions-url]

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Paypal Donation][paypal-badge]][paypal-url]

[crates-badge]: https://img.shields.io/crates/v/rama-http-core-core.svg
[crates-url]: https://crates.io/crates/rama-http-core
[docs-badge]: https://img.shields.io/docsrs/rama-http-core/latest
[docs-url]: https://docs.rs/rama-http-core/latest/rama_http_core/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.96+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/actions/workflows/CI.yml/badge.svg?branch=main
[actions-url]: https://github.com/plabayo/rama/actions/workflows/CI.yml

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo
[paypal-badge]: https://img.shields.io/badge/paypal-contribution?style=for-the-badge&color=blue
[paypal-url]: https://www.paypal.com/donate/?hosted_button_id=P3KCGT2ACBVFE

🦙 rama® (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).

## rama-http-core

Rama http protocol implementation and low level utilities.

Forked from [`hyper`] and [`hyper-util`] with the goals of contributing
upstream where we can. Rama's requirements do not however match 1-on-1
with [`hyper`] given we want the ability to be able to deviate from RFC's
where is required and also expose more low level control than is required
for most other http purposes.

This crate is used by [`rama-http-backend`] and thus also [`rama`].

Crate used by the end-user [`rama`] crate and `rama` "http" crate authors alike.

### Request priority on HTTP/2

Insert `h2::client::RequestPriority` into a request's extensions to use an
exclusive dependency chain ordered by encoded weight (`0..=255`). Higher
weights form higher-priority bands. A request depends on the last live stream
in the nearest band at or above its own; equal-weight streams retain their
opening order. Requests without this extension keep their existing behavior.

Keep a clone of the control to call `set_weight` while a request is in flight.
Changes before the first HEADERS update its initial priority. Later changes
update the connection's ordering, emitting PRIORITY frames only when the parent
changes. Child reconnections precede the moved stream's update, and both precede
later HEADERS. Call controls in the intended order rather than sending changes
through independently polled request queues.

Use a separate control for each concurrent request. Reusing a control while
its stream is live returns a rejected-request error. After stream closure, you
can reuse it for a retry or redirect; it retains the latest weight. Controls
hold weak connection references and do not keep streams alive. The caller owns
resource classification and chooses the weights; this crate does not identify
browser resource kinds or schedule visibility-driven promotions.

The connection store owns dependency membership and pending priority frames.
`src/h2/proto/streams/streams/priority.rs` owns the control and dependency
ordering, adapted from Chromium's `Http2PriorityDependencies` at revision
`3188f8a607ae7e067593be8aab7f02d2451fec07` under its adjacent
`CHROMIUM-LICENSE`. `tests/h2_priority.rs` exercises the public client and wire
format, including lifecycle, ordered changes, and fragmented HPACK.

Learn more about [`rama`]:

- Github: <https://github.com/plabayo/rama>
- Book: <https://ramaproxy.org/book/>

[`hyper`]: https://github.com/hyperium/hyper
[`hyper-util`]: https://github.com/hyperium/hyper-util
[`rama`]: https://github.com/plabayo/rama
[`rama-http-backend`]: https://github.com/plabayo/rama/tree/main/rama-http-backend
