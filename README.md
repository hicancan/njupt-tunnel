# sdp-tunnel

**English** · [简体中文](README.zh-CN.md)

A userspace client for an enterprise SDP gateway. It authenticates, opens the
gateway's L3 tunnel, runs its own TCP/IP stack on the address the gateway
assigns, and offers that network as a local SOCKS5 and HTTP proxy.

No TUN driver, no administrator rights, no change to the host routing table.
One static binary.

```
application ──► SOCKS5 127.0.0.1:1080        ┌─ controller API over TLS
            └─► HTTP   127.0.0.1:8080        │   key, captcha, login, policy
                        │                     │
                        ▼                     ▼
                 userspace TCP/IP  ──►  framed L3 tunnel over TLS  ──►  gateway
                 (gVisor netstack)       on the assigned virtual IPv4
```

## Why userspace

A conventional VPN client installs a virtual adapter and rewrites the routing
table, which needs a driver and elevation. This one terminates TCP and UDP in
process and hands the result to whatever asks over a loopback proxy port. The
practical consequences:

- runs as an unprivileged user,
- leaves the host's own networking untouched, so it coexists with any other
  VPN, proxy or TUN tool already present,
- the routing decision belongs to whatever you point at the proxy.

## What is implemented

- Authentication: session key, captcha, AES-128-CBC password wire format,
  session cache with atomic replacement.
- Session renewal without a captcha when the controller rejects a cached
  session, falling back to a full login only if renewal fails.
- Framed L3 tunnel over TLS, with the virtual address and netmask taken from
  the gateway's own handshake attributes.
- Userspace IPv4 TCP and UDP on the assigned address, with DNS resolved
  through the tunnel against the resolver named by the authenticated policy.
- SOCKS5 (`CONNECT` and `UDP ASSOCIATE`) and HTTP proxy (`CONNECT` and plain
  forwarding) inbounds.
- Address lease registration and release against the controller.
- Reconnection that rebuilds an entire generation — new stack, new sockets —
  so no state crosses a disconnect, and that drops connections pooled on the
  tunnel that died.

Not implemented: IPv6 (the gateway assigns none), the single-packet
authorization knock (disabled by the deployments this was tested against), and
a second transport some clients use. Each omission is a measured decision, not
an oversight.

## Download

Every release carries a static binary for Windows, Linux and macOS on x64 and
ARM64, with `SHA256SUMS` to check it against:
[the latest release](https://github.com/hicancan/sdp-tunnel/releases/latest).
There is nothing to install — put a `config.json` beside the binary and run it.

## Build

Needs Go 1.27 or newer and nothing else.

```sh
go build -trimpath -ldflags='-s -w' -o bin/sdp-tunnel ./cmd/sdp-tunnel
go test ./...
```

`go test -race ./...` additionally needs a C toolchain.

## Configure

Copy `config.example.json` to `config.json` and fill it in. Every value that
differs between deployments lives here; the code contains none of them.

| Field | Meaning |
|---|---|
| `gateway.host`, `gateway.port` | the gateway endpoint |
| `gateway.bind_ip` | optional local source address; omit it on a single-homed host and let the operating system route |
| `gateway.ca_file` | optional extra PEM roots, added to the system trust store rather than replacing it |
| `gateway.mtu` | tunnel MTU, 1400 by default |
| `protocol.api_base` | path prefix of the controller API |
| `protocol.user_agent` | the client identity string the controller expects |
| `protocol.session_cookie` | name of the cookie that binds key, captcha and login |
| `protocol.renew_salt` | salt the controller expects in the session-renewal digest |
| `captcha.model` | path to a captcha model file, see below |
| `auth.username`, `auth.password` | credentials; both may be omitted if a cached session is enough |
| `inbounds` | one or more `socks5` or `http` listeners |

Paths inside the file are resolved relative to the file. `config.json` is
ignored by git, and so is every `.bin`, so neither your credentials nor your
model can be committed by accident.

### The captcha model

Logging in means reading the controller's captcha. This repository ships the
recognition **engine** but no model: a trained model is specific to one
gateway's captcha, so it is a deployment artifact like any credential.

Point `captcha.model` at a model file. The format is self-describing, so the
engine holds no constants belonging to any particular captcha:

```
offset  size       field
0       4          magic "MCNN"
4       4          version = 2
8       4          image width
12      4          image height
16      4          character slots
20      4          inset: a glyph is scaled to fit this many pixels of the 32x32 cell
24      4          background threshold: a pixel whose every channel is >= this is background
28      4          noise run: a colour spanning more columns than this is an interference line
32      4          alphabet length N
36      N          alphabet bytes (ASCII)
36+N    slots * 8  fallback spans, each a (start, end) pair of uint32
...     12         topology: first-layer filters, second-layer filters, dense units
...                weights: conv1 w/b, conv2 w/b, dense1 w/b, dense2 w/b, little-endian float32
```

The alphabet is an index-to-character table and may repeat an entry, which is
how a model whose classes distinguish letter case can still report one case:
the engine performs no folding of its own.

The engine runs one fixed topology — a 3x3 convolution, ReLU and 2x2 pooling
twice over a 32x32 glyph cell, then two dense layers — and refuses a model
declaring any other, rather than running it wrong. Its limits are 320x96
pixels, 8 slots and 95 classes.

Without a model the client still resumes a cached session; it just cannot log
in from scratch.

## Run

```sh
./sdp-tunnel -c config.json          # serve the configured inbounds
./sdp-tunnel -c config.json -check   # validate a cached session and the handshake only
./sdp-tunnel -v                      # version
```

Then send the traffic you want tunnelled to the proxy. With a routing client
such as sing-box or Xray, declare the local SOCKS5 port as an outbound and
match the destinations that belong behind the gateway. Two rules matter:

1. The gateway's own address must be reached **directly**. A rule that sends
   it through this proxy would ask the tunnel to carry its own transport.
2. Put that direct rule **before** any broad rule that would otherwise match
   the gateway's hostname.

## Known behaviour

**The gateway terminates each tunnel after roughly nine minutes.** Measured
across independent runs, the disconnections land on a fixed second offset
within the minute, which identifies a scheduled sweep on the gateway rather
than anything the client does or fails to do. It is not an idle timeout: the
interval does not depend on traffic, and no keepalive prevents it.

The client reconnects in about a second, reusing the cached session, and drops
connections pooled on the dead tunnel so a caller sees a reconnect rather than
a broken stream. Streams in flight at that moment do end — their data path is
gone — and no client-side change can avoid that.

## Scope

This is an independent client, written from observed protocol behaviour and
not affiliated with or endorsed by any vendor. Use it with your own
credentials, on a network you are authorised to use, in accordance with
whatever terms apply to your account. It automates the login you are already
entitled to perform; it does not bypass authentication, and it grants no
access that your own credentials do not.

## License

MIT, see [LICENSE](LICENSE).
