# vulsweb

A web UI for [vuls](https://github.com/future-architect/vuls) scan results,
built to replace [VulsRepo](https://github.com/ishiDACo/vulsrepo) (which stopped
following the vuls JSON format around v0.19). Works with vuls v0.43.

Ships as a **single executable** (built with [burrito_ng](https://hex.pm/packages/burrito_ng))
and a **distroless** container image. No database: it reads the JSON files that
`vuls server -to-localfile` (or `vuls scan`/`vuls report`) writes.

- **Fleet dashboard**: latest scan of every host, severity counts, stale hosts,
  reboot required, KEV and public-exploit counts, a "fix these first" list.
- **Host view**: filterable and sortable CVE list (severity, fix status, KEV,
  exploit, free-text search across CVE, package and description), installed and
  upgradable packages, scan history with trend, the diff against the previous
  scan, and scan errors and warnings.
- **Vulnerabilities**: every CVE across the fleet, with affected hosts and packages.
- **CVE detail**: CVSS v2/v3/v4 from every source, descriptions per source, KEV
  details, exploits and Metasploit modules, CWE, distro advisories, mitigations,
  references, and per host which package, which version, and the fixed version.
- **Live**: new results show up in open browsers without a reload.
- **CSV export** of any filtered view. Optional **basic auth**.
- mudrock.dev light and dark themes (daisyUI), self-hosted fonts, works offline.

Severity, scores and fix status are computed exactly like `vuls report` / `vuls tui`
(`MaxCvssScore`, `CountGroupBySeverity`, `PatchStatus`).

## How results are found

`vuls server -to-localfile` writes one file per POSTed scan to
`results/<scannedAt>/<server>.json`. The directory name is *that host's* scan
time, so hosts end up in different directories. vulsweb indexes the whole tree
and treats the newest file of each host as its current state. Older files form
the host's history.

The directory is polled (default every 15s). Only new or changed files are
parsed, and files modified in the last 2 seconds are skipped until vuls finishes
writing them. A truncated or broken newest file never hides the last good scan.

## Supported result files

Every result file written by **vuls v0.5.0 (2018) or newer** (`"jsonVersion": 4`)
is supported, including folders from `vuls scan`/`vuls report` and
`vuls server -to-localfile`. Older layouts inside v4 are normalized on read
(`Vulsweb.Vuls.Compat`):

| vuls version | difference | handled |
|---|---|---|
| < v0.15.14 | `cveContents.<source>` is an object, not a list | yes |
| < v0.19.0 | `alertDict` is `{en, ja}` instead of `{cisa, jpcert, uscert}` | yes |
| < v0.23.0 | result folders named RFC 3339 (`2021-06-01T10:00:00+09:00`) | yes |
| v0.9 – v0.12 | library scans under `libScanners` instead of `libraries` | yes |
| older | GitHub alerts with `packageName` instead of `package.name` | yes |
| < v0.5.0 | jsonVersion 2/3 or no version (a different format) | shown as unreadable, with the reason |

Fields added in later releases (CVSS v4.0, KEV catalogs, EUVD, SSVC, ...) are
simply absent from older files. Files from a future `jsonVersion` are read on a
best-effort basis.

## Running with docker compose

Next to your existing vuls server (replacing the `vulsrepo` service):

```yaml
services:
  vuls-server:
    image: vuls/vuls
    container_name: vuls-server
    restart: unless-stopped
    volumes:
      - ./data:/vuls
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "100.110.1.1:5515:5515"
    command: server -listen=0.0.0.0:5515 -to-localfile -config=./config.toml

  vulsweb:
    image: vulsweb            # or: build: ./vulsweb
    container_name: vulsweb
    restart: unless-stopped
    # vuls runs as root and writes results with mode 0700/0600, so vulsweb has
    # to read them as root. Everything else is locked down.
    user: "0:0"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    # The binary unpacks its runtime to /tmp on start: needs exec (docker's
    # tmpfs default is noexec).
    tmpfs: ["/tmp:exec,size=128m"]
    # Forwards `docker stop` to the binary (it runs as PID 1 otherwise).
    init: true
    environment:
      VULS_RESULTS_DIR: /vuls/results
      # VULSWEB_AUTH_USER: admin
      # VULSWEB_AUTH_PASSWORD: change-me
    volumes:
      - ./data/results:/vuls/results:ro
    ports:
      - "100.110.1.1:5111:5111"
```

Then open `http://100.110.1.1:5111`. `GET /healthz` returns 200 once the results
directory is readable (it is not behind basic auth).

## Running the binary

```sh
VULS_RESULTS_DIR=/srv/vuls/data/results ./vulsweb_linux_amd64
```

On first start the binary unpacks its payload (Erlang runtime and app, about 1s)
to `$XDG_DATA_HOME/.burrito_ng` (default `~/.local/share/.burrito_ng`). Override it
with `VULSWEB_INSTALL_DIR`. The binary is statically linked and has no runtime
dependencies. It needs a writable `/tmp` for its bundled musl loader.

## Configuration

All configuration is through environment variables:

| Variable | Default | |
|---|---|---|
| `VULS_RESULTS_DIR` | `/vuls/results` | vuls results directory |
| `BIND` | `0.0.0.0` | listen address (IPv4 or IPv6) |
| `PORT` | `5111` | listen port |
| `VULSWEB_REFRESH` | `15` | seconds between results directory scans |
| `VULSWEB_STALE_AFTER` | `48` | hours after which a host is flagged stale |
| `VULSWEB_AUTH_USER` / `VULSWEB_AUTH_PASSWORD` | unset | enable HTTP basic auth (set both) |
| `PHX_HOST` | `localhost` | host name used in generated absolute URLs |
| `SECRET_KEY_BASE` | random per boot | cookie signing key, set it to keep sessions across restarts |
| `VULSWEB_INSTALL_DIR` | `~/.local/share` | where the binary unpacks itself |

Basic auth sends credentials in clear text. Put vulsweb behind TLS (or a VPN, like
the Tailscale address above) if you enable it.

## Development

Toolchain versions are pinned in `mise.toml` (Erlang, Elixir, bun, Rust).
Elixir deps come from Hex. UI deps (Tailwind, daisyUI, Lucide icons, topbar, fonts)
come from npm through bun. The Phoenix JS clients are resolved from `deps/`
(see `assets/tsconfig.json`), not npm.

```sh
mise install
mix setup                   # deps.get, bun install, build assets
mix vulsweb.gen.sample      # writes realistic sample results to ./sample/results
mix phx.server              # http://localhost:4000
mix test                    # or: mix precommit
```

## Building

```sh
# single binaries in burrito_ng_out/ (linux_amd64, linux_arm64)
MIX_ENV=prod mix assets.deploy
MIX_ENV=prod mix release                                  # all targets
MIX_ENV=prod BURRITO_NG_TARGET=linux_amd64 mix release    # one target

# container image (multi-arch with buildx)
docker build -t vulsweb .
docker buildx build --platform linux/amd64,linux/arm64 -t vulsweb .
```

burrito_ng needs a pre-compiled musl ERTS for the **exact** OTP version you
build with. That is why `mise.toml` pins `erlang = "29.1"`: beam-machine
publishes 29.1 but not 29.1.x patch releases.

burrito_ng only unpacks a payload whose app version isn't installed yet. **Bump
the version in `mix.exs` for every build you deploy**, otherwise hosts that
already ran an older build keep running its unpacked code. Or delete the install
dir (`./vulsweb_linux_amd64 maintenance directory` prints it).

## Releasing

Push a version tag:

```sh
git tag v1.2.3
git push origin v1.2.3
```

`.github/workflows/release.yaml` then:

1. runs the format check, a warnings-as-errors compile and the test suite,
2. builds the single-file binaries for linux amd64 and arm64 and a multi-arch
   image, from the same Dockerfile and with a shared build cache,
3. pushes the image to `ghcr.io/<owner>/<repo>` with tags `1.2.3`, `1.2` and
   `latest`, plus provenance and an SBOM,
4. creates a GitHub release with `vulsweb_1.2.3_linux_{amd64,arm64}` and `SHA256SUMS`.

The tag sets the app version (`VULSWEB_VERSION`), so `mix.exs` doesn't need a
bump. Tags with a suffix (`v1.2.3-rc.1`) create a pre-release and leave `1.2` and
`latest` alone. The first push creates the GHCR package as private; make it
public in the package settings if anyone should pull it without logging in.

## License

Copyright (C) 2026 MUDROCK SOFTWARE LTD

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program (see [LICENSE](LICENSE)). If not, see <https://www.gnu.org/licenses/>.
