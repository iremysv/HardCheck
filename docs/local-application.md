# Local application: Ubuntu installation and acceptance

This extension follows the existing step-01 through step-10 work; it does not
rename those steps. It adds a local application flow to the existing CLI and
static panel. No site deployment or visibility change is part of installation.

## First installation or upgrade

Use the updated source tree in `~/HardCheck`. The old Ubuntu scan results do not
validate this code. Commit/push and source synchronization are left to the user.
Python 3.12, Git and `python3-venv` are assumed installed.

Run once in an Ubuntu terminal, as your ordinary user:

```sh
cd ~/HardCheck
.venv/bin/python -m pip install .
.venv/bin/hardcheck install-launcher
```

For a new checkout without a virtual environment, first run
`python3 -m venv .venv`. Keep the project and `.venv` at this location: the launcher
records the absolute virtual-environment Python path. If the folder moves,
reinstall the launcher from the new environment. No activation is required.

Open Ubuntu's application menu, search for **HardCheck**, and click it. This is
an application-menu entry, not a file that needs “Allow Launching” on the desktop.
The entry is `~/.local/share/applications/hardcheck.desktop` (or the corresponding
`XDG_DATA_HOME` location). No sudo, system service or login autostart is installed.

## Daily use: no terminal

1. Click **HardCheck** in the application menu. It starts the local service and
   opens `http://127.0.0.1:8765/` in the default browser.
2. Click **Gerçek taramayı başlat**. The page shows running/completed/error state;
   a running scan disables the button in every connected tab.
3. Review findings and expand **Gözlem / kanıt**. Status/severity/category/search,
   pagination and comparison continue to work. Completion is not a security
   verdict: WARN/SKIP/ERROR remain explicit, and the score covers PASS/FAIL only.
4. Click **Son tarama · JSON indir** and **Son tarama · HTML indir**. The browser
   saves the same completed scan; neither button runs checks again. The existing
   **Görüntülenen raporu JSON indir** exports the currently displayed report, including manually
   loaded reports. The two actions are intentionally labelled differently.
5. Click **Gerçek taramayı başlat** again to rescan. During a new or failed attempt,
   the previous displayed scan is marked **ÖNCEKİ TARAMA**, and local exports are
   disabled. Successful scans enter the existing in-tab comparison history.

Closing the browser does not stop the service. Clicking the launcher again
verifies and reopens that service; it does not start a second instance. The
service and report memory are not persisted across logout/restart. Comparison
history belongs to the tab; refreshing can restore the current completed local
scan but not the tab's older history. Imported files stay in browser memory.

After upgrading an already-running version, log out and back in before opening
the launcher to ensure the new code is running. There is no automatic process
termination. A conflicting port or unverifiable instance produces a browser
error page; no unknown process is killed. Error pages in the system temporary
directory contain only fixed diagnostic text, never reports or tokens.

On macOS, the panel can be served for development, but the real-scan button is
disabled with an explicit Linux-only message. The existing CLI still returns
SKIP for unsupported platforms. The Linux launcher installer rejects macOS.

## Remove

```sh
cd ~/HardCheck
.venv/bin/hardcheck uninstall-launcher
.venv/bin/python -m pip uninstall hardcheck
```

Removal preserves unrelated desktop entries and downloaded reports. Log out to
stop a running service before uninstalling or removing its environment. After it
has stopped, the private `hardcheck` runtime directory may be removed if desired.
Never delete or replace `instance.lock` while a service is running.

## Design and security boundary

- The standard library HTTP server has a small fixed routing surface. No Flask,
  subprocess CLI wrapper or new runtime dependency is needed. It is exclusively
  a loopback desktop companion, not a general production web server.
- It binds only IPv4 `127.0.0.1`. Host must exactly match `127.0.0.1:<port>`;
  an Origin, when present, must exactly match `http://127.0.0.1:<port>`.
  Cross-site/same-site fetch metadata is rejected; no CORS permission is sent.
- A 256-bit random HttpOnly/SameSite=Strict session cookie and a separate 256-bit
  CSRF token protect API calls. The token is inserted into the same-origin HTML
  response, never a URL, browser storage or request log. A scan requires POST,
  exact Origin, cookie, custom CSRF header and an empty body. GET never scans.
  Normal page and download GETs can omit Origin. All responses use no-store,
  frame denial, no-referrer and restrictive CSP. Plain HTTP stays on loopback;
  the cookie deliberately has no Secure flag for this HTTP-only transport.
- Sessions expire after eight hours on both the server and cookie. Restart
  HardCheck after expiry; reloading the page does not extend the server deadline.
  At most 16 HTTP connections have workers, each with a ten-second total
  connection deadline (including slowly delivered headers) and a 16 KiB
  aggregate header budget. Excess connections are closed before worker creation.
- The threat boundary is hostile websites, cross-origin requests and DNS
  rebinding, not malicious software already running on this computer. Other
  local processes can make loopback requests; the local account, browser and
  installed code must be trusted. Do not expose this server through a proxy,
  tunnel or port forwarding. The panel has no remote report upload route.
- `ScanManager` owns scan admission and state; `engine.py` has no global lock.
  Checks run directly in one worker. Concurrent requests receive 409 rather
  than waiting for the scan. Both exports must render successfully before
  publishing completion. Errors clear current exports and permit retry.
- Only fixed scans and bundled assets are exposed. There is no arbitrary
  command, Python expression, configuration upload or filesystem-path API.
  No elevation, settings mutation or remediation is performed.
- The runtime directory is `$XDG_RUNTIME_DIR/hardcheck`, falling back to
  `~/.local/state/hardcheck`, with mode 0700 and ownership validation. Runtime
  files are 0600 regular files; symlinks and hardlinks are rejected. `flock`
  owns the instance lifetime; the lock inode stays stable. A private random key
  authenticates reuse with a fresh HMAC challenge. A PID alone is never trusted.
  Stale state can be replaced only after acquiring the operating-system lock.
- Launcher installation validates the opened application directory and file,
  rejects shared directories, symlinks, hardlinks and special files, and reads
  the managed marker through the same descriptor used for writing. New files
  use exclusive creation; existing unrelated entries are preserved. Ancestor
  directories and processes running as the same user remain trusted.
- Reports remain in service memory until replaced or the process ends. They use
  the existing sanitized report contract; raw probe output, password hashes and
  exception details are never added. Downloaded files are private user data;
  store them outside Git or in ignored `scan-output/`.

## Evidence correction

The report contract is a list of `{key, value}` pairs, already understood by the
panel. `NET-002` previously collected TCP observations but omitted structured
facts, triggering `BaseCheck`'s `assessment: unknown` fallback even for PASS.
It now records observed TCP 21/23 listener counts and complete/partial coverage.
A zero count with partial coverage does not prove absence; statuses are unchanged.
The panel also formats `mode_bits` as octal, matching the Python HTML/terminal
format. Existing unknown evidence is retained; old JSON files are not rewritten
or supplied with guessed values. New scans are needed to collect the new facts.

## Validation record (2026-10-20)

Development verification used macOS, Python 3.14 and synthetic fixtures:

- 447 Python tests passed, including HTTP security, duplicate Host/Origin,
  concurrent scan rejection, errors, rendering errors, retry, exports, launcher
  permissions/reuse/port conflict and the existing CLI/check tests.
- 16 Node DOM-stub tests passed. The evidence regression passes Python-generated
  JSON from synthetic TCP tables into the actual panel rendering code.
- An isolated wheel install passed the existing 18-control report/CLI validator
  and the new `serve`/resource/authentication/reuse validator from an unrelated
  working directory. The source archive is rebuilt into a wheel by packaging
  tests. `web/dist/` remains the sole asset source; `setup.py` copies its explicit
  allowlist into `hardcheck/web/` during builds.
- Real headless Chromium exercised idle/running/completed/error, two tabs,
  rescan, evidence details, JSON/HTML download byte equality, history, comparison,
  manual upload, demo and unsupported-platform messaging. Desktop (1440×1000) and narrow (390×844) screenshots
  were inspected; narrow layout had no document-level horizontal overflow.
- Ruff, Bandit and `pip check` passed. The manually triggered CI workflow now
  also runs the Node contract tests and installed local-service validator; it
  has not been run remotely for these uncommitted changes.
- These are not Ubuntu/Firefox, Python 3.12 or live Linux audit results. UTM
  desktop launch and the real Linux acceptance sequence below remain pending.

Reproduce development checks:

```sh
.venv/bin/python -m pip install -e '.[dev,security]'
PYTHONPATH=src .venv/bin/python -m pytest -q
node --test web/tests/report.test.cjs
.venv/bin/ruff check src tests scripts setup.py
.venv/bin/bandit -q -r src scripts -c pyproject.toml
```

For optional real-browser checks, install `playwright` into the development
virtual environment and provide an installed Chromium executable:

```sh
PYTHONPATH=src .venv/bin/python scripts/validate_local_browser.py \
  --browser /path/to/chromium --output artifacts/local-browser
```

Run `scripts/validate_install.py` and `scripts/validate_local_install.py` with a
fresh virtual environment's Python after installing the built wheel, without
PYTHONPATH. These validators never audit the host.

## Pending Ubuntu/UTM acceptance with the user

1. Synchronize this updated source to `~/HardCheck`, install it and install the
   launcher using the first-installation commands above.
2. Click HardCheck in Ubuntu's application menu. Confirm Firefox opens the exact
   loopback address and initially says no real scan has run. Click the launcher
   again and confirm the existing idle/running/completed session is reused.
3. Click **Gerçek taramayı başlat**. Confirm running state, disabled repeat button
   and automatic findings without moving any files. Open a second tab during
   the scan to confirm the same state. Record the new PASS/FAIL/WARN/SKIP/ERROR
   counts; the earlier 7/3/4/4/0 result is not an expected-value assertion.
4. Expand NET-002 and a filesystem finding. Check listener counts/coverage and
   octal permission bits against the newly downloaded JSON. Genuine unknown
   observations must remain unknown.
5. Download JSON and HTML. Open the HTML offline and confirm the same findings
   and counts as JSON; downloading must not change scan generation or start a
   scan. Narrow the Firefox window and confirm usable controls and details.
6. Rescan, compare the two completed reports, then load an existing JSON file and
   switch to the sample report. All three paths should remain distinct.

Send the new counts and any failing step (without password data or full private
reports). A reproducible unexpected error will be investigated before calling
Ubuntu acceptance complete.

## Panel clarity follow-up

The local application now keeps the sample-scan entry in Help, while the static
viewer retains its heading action. PASS, FAIL, WARN, SKIP and ERROR have separate
summary counts. The score card displays assessed/total controls and coverage;
these values are calculated from the displayed report, never a user recording.
The displayed-report JSON export is labelled separately from latest-scan exports.
Reviewing a local scan from tab history preserves its previous-scan source label.
Concurrent status refreshes cannot insert the same scan into history twice.

User-provided Ubuntu video showed a local scan completing, automatic findings
and a JSON export opening. This is observational evidence, not a complete Ubuntu
acceptance run. Launcher startup, opened HTML/JSON agreement, repeat scans,
comparison and simultaneous tabs still need user verification there. A connection
error in a tab preview could not be attributed to the active service. No recording,
frames or user report data are included in this change.

Follow-up validation on macOS: 447 Python tests and 19 Node panel tests passed;
Ruff, Bandit and relative documentation links passed. Real Chromium with synthetic
checks passed at 1440px and 390px, including sample access from Help, distinct
outcome counts, score coverage, download labels, retry and comparison. Screenshots
were inspected. This does not replace the remaining Ubuntu acceptance steps.
