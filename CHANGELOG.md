# Changelog

All notable changes to **McSsCheck** are listed here. Format inspired by
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [0.9.7] — 2026-05

Follow-up hotfix to v0.9.6. On machines whose default `.html` UserChoice
ProgId points at a browser whose ShellOpen template wraps `%1` in
quotes — e.g. Chrome's `"...chrome.exe" --single-argument "%1"` or
Firefox's `"...firefox.exe" -osint -url "%1"` — clicking **Open HTML
report** would land in the browser's address bar with a literal pair of
surrounding double-quotes (e.g. `"file///C:/Users/.../mcss-report-...html"`).
Chrome treated the quoted blob as a search query and showed
`DNS_PROBE_FINISHED_NXDOMAIN` instead of opening the report.

### Fixed

- **`HtmlReportRenderer.SplitCommandLine`** now matches the
  already-quoted placeholder forms (`"%1"`, `"%L"`, `"%l"`) **before**
  the bare ones (`%1`, `%L`, `%l`), and stops after the first match.
  Previously the bare `%1` was found first inside `"%1"`, replaced with
  `"file:///..."`, and the outer quotes were left untouched — producing
  `--single-argument ""file:///...""`. Chrome's `--single-argument` flag
  preserves the rest of the raw command line verbatim, so the surplus
  quotes leaked straight into the address bar. Reorder + early `break`
  fixes both Chrome and any other browser whose UserChoice ProgId wraps
  `%1` in quotes.
- The substitution loop also accepts lowercase `%l`, which a few
  non-default associations use.

### Compatibility

- No flag changes. CLI surface identical to v0.9.6.
- Existing HTML reports from older versions still open the same way
  (the fix is 100% on the launching side).

## [0.9.6] — 2026-05

Hotfix for the "Internet Explorer 11 is no longer supported" popup some
users hit on Windows Server / locked-down VMs when clicking **Open HTML
report**. On those machines, Windows still has IE11 wired up as the
default handler for `.html`, so the v0.9.5 shell-execute call ended up
in IE, which Microsoft retired in 2022 and which now only shows the
popup instead of rendering anything.

### Changed

- **`HtmlReportRenderer.OpenInBrowser`** no longer relies on
  `ProcessStartInfo.UseShellExecute = true`. Instead it walks a
  four-step fallback ladder that skips IE entirely:
  1. Resolve the user's `UserChoice` ProgId from the registry for
     `.html`, `.htm`, `http://`, and `https://` — in that order.
     Any ProgId that looks like Internet Explorer
     (`IE.*`, `Iexplore.*`, `InternetExplorer.*`) is skipped, and
     the remaining ProgId's ShellOpen command is executed directly.
  2. If no good UserChoice exists, try known install paths of
     Edge, Chrome, Brave, Firefox, Vivaldi and Opera in that order.
     Edge is always present on modern Windows, so this step
     succeeds on any default-imaged machine.
  3. `explorer.exe <file>` — opens the file through the shell's
     document-open path (still file-association based but modern
     Windows almost never routes that to IE).
  4. `explorer.exe /select,<file>` — last resort: highlight the
     file in Explorer so the user can drag it into a browser
     window manually.
- **GUI: new "Show in folder" button** next to "Open HTML report".
  It calls the new `HtmlReportRenderer.ShowInFolder(path)` helper
  and pops Explorer open at the report with the file selected.
  Useful when the player has a non-standard browser that the
  fallback ladder hasn't heard of.

### Compatibility

- No flag changes. CLI surface identical to v0.9.5.
- Existing HTML reports from older versions still open the same way
  (the fallback change is 100% on the launching side).

## [0.9.5] — 2026-05

Detection-upgrade + housekeeping release. Two themes:
1. Catch more cheats — in particular the "javaagent" family
   (Doomsday, Weave, Koid, rebuilt Atermys jars, …) that survives
   every name-based check because the filename can be anything.
2. De-duplicate scanner plumbing that had accumulated — three
   copies of a quote-aware cmdline tokenizer, two copies of the
   "user-controlled folders" list, and scattered manifest-parsing
   bits.

### Added

- **`JavaAgentScanner`** — new scanner, enabled by default.
  Reads `META-INF/MANIFEST.MF` from every `.jar` in the scoped
  folders (Desktop / Downloads / Documents / Public / AppData /
  LocalAppData / %TEMP% / profile root **and** `.minecraft/mods/`
  + `.minecraft/versions/`) and flags jars that declare
  `Premain-Class` or `Agent-Class`. Legitimate Minecraft mods
  (Fabric / Forge / NeoForge / Quilt / vanilla) never declare a
  JVM-level agent — every cheat-agent family we've seen does.
  One card per jar, tagged `java-agent` + `manifest-agent` (plus
  any cheat-keyword tag that matched the agent class / main class
  / filename) so the HTML report's cross-source dedup collapses
  it with the matching Process / Recent / Registry hits.
- **`--no-agent-scan` CLI flag** — opt out of the new scanner,
  mirroring the existing `--no-exe-scan` / `--no-*` knobs.
- **`JarManifestInspector`** utility — the shared MANIFEST.MF
  parser (handles continuation lines and the CRLF/CR/LF delimiter
  soup) used by the new scanner. Public helpers: `Read(jarPath)`
  and `IsJavaAgent(manifest)`.

### Detection database expansion

- `KnownCheats.NameKeywords` — **~25 new entries** covering
  2025-2026 clients and loaders seen on screenshare: Koid,
  Atermys, Slinky.gg / Pluto Solutions, Orion, Zenith, Vivid,
  Solaris, Trident, Nexus, Astrolabe, Venom, Mistral, Raptor,
  Inferno, Polaris, Eclipse, Obsidian, Titan, Thunder client.
- `KnownCheats.CheatDomains` — **~18 new entries** (slinky.gg,
  t.me/plutosolutions, atermys.{com,gg,cc}, koidclient.com,
  orion-client.com, zenithclient.cc, vividclient.cc,
  solarisclient.org, tridentclient.cc, nexusclient.cc,
  venomclient.cc, infernoclient.cc, obsidianclient.cc,
  titan-client.cc, eclipsecheat.io, …).
- `KnownCheats.InternalKeywords` — **new package-path fragments**
  that appear inside cheat agent jars (`net/java/f/`, `dev/koid/`,
  `gg/slinky/`, `net/atermys/`, `com/atermys/`, `net/weavemc/`,
  `net/doomsday/`) plus the agent-bootstrap strings (`premain`,
  `agentmain`, `lang/instrument/`). Catches obfuscated jars whose
  class names are scrambled but whose package path leaks.
- `CheatFingerprints.BinaryMarkers` — **new markers for Koid,
  Weave Loader, Orion, Zenith**, plus extra banners for Atermys
  (overlay title, config header), Slinky.gg (`SlinkyInjector`,
  `slinky_config`) and Doomsday's `net.java.f` premain-class
  signature.

### Changed (tidying)

- **`Util/CmdlineTokenizer`** — new helper; single quote-aware
  cmdline tokenizer used by `ProcessScanner`, `LiveJvmScanner`.
  The three identical local copies have been deleted.
- **`Util/UserFolders`** — new helper; returns the user-scoped
  folder list (with `GetDefaultRoots()` and a lighter
  `GetDropFolders()` variant for the ADS heuristic).
  `CheatExeScanner.CollectRoots` and
  `HeuristicEngineScanner.AdsScriptStreamModification` now call
  it instead of re-building the list twice, so they can never
  drift apart again.
- Version in `McSsCheck.csproj`, assembly version, file version
  and informational version bumped to **0.9.5** — the live-wired
  value shows up automatically in the HTTP `User-Agent` of the
  Modrinth / VirusTotal clients and in the HTML report header.

### Compatibility

- No breaking changes. CLI surface is identical to v0.9.4 except
  for the new opt-out `--no-agent-scan` flag.
- The new scanner is opt-out: omit the flag to use it (default),
  pass it to skip.
- The DB expansions only add new entries; nothing removed.
  Existing reports and tag-based dedup keep working as before.

## [0.9.4] — 2026-05

Visibility patch on top of v0.9.3. Two complaints from the first
v0.9.3 user:
1. **Discord Accounts (0)** — even though the in-app Switch-account
   menu listed signed-in accounts, the report showed zero.
2. **Cheat-exe scanner silent on success** — when the renamed-cheat
   detector ran but hit nothing, the section was empty in the
   report, so the user couldn't tell whether it had actually walked
   any folders or just bailed out.

### Changed

- **`DiscordAccountScanner` deepened.** Up to v0.9.3 we only read
  `Local Storage\leveldb\*.log` (a single file) — modern Discord
  builds rotate that data into `.ldb` snappy-tables almost
  immediately, leaving the log empty. v0.9.4 now scans:
  - `Local Storage\leveldb\*.log` and `*.ldb` (snappy-framed but
    JSON literals usually survive),
  - `Session Storage\` (per-session redux state cache),
  - `IndexedDB\` recursively (per-origin leveldb folders such as
    `https_discord.com_0.indexeddb.leveldb/`),
  - the manifest files for completeness.
  Bytes are decoded both as UTF-8 and as UTF-16-LE so widechar
  resources hit the regex too.
- **New extraction strategy.** Added a `MULTI_ACCOUNT_STORE`
  pattern alongside the existing `_remoteAuth_recentAccounts` and
  inline-`{"id":..,"username":..}` patterns, and a per-id merge
  step that backfills `global_name` / `avatar` from later strategies.
- **Discord scan now emits a "scan summary" Info card** when no
  account is found, listing per-variant file counts (Discord /
  PTB / Canary / Development) so the user can tell whether the
  scanner walked anything at all vs. found data and chose not to
  match.
- **`CheatExeScanner` gained a "scan summary" Info card** at the
  end of every run, regardless of detect count. The card lists:
  - folders walked + total candidate files / bytes,
  - per-extension breakdown (`.exe`, `.dll`, `.jar`, `.zip`),
  - hash hits + marker hits,
  - per-folder counts (which roots had how many candidates),
  - any enumeration errors (e.g. permission denied on a folder).
  This is the difference between "scanner was a no-op" and
  "scanner walked 12 000 files in Downloads, found nothing
  matching the DB" — staff can now tell which case they're in.

### Compatibility

- No breaking changes. No new flags. Existing CLI surface and
  scanner ordering identical to v0.9.3.

## [0.9.3] — 2026-05

Headline detection feature. Up to v0.9.2 every cheat-detection
scanner trusted the *file name* — `vape.exe` matched because it
was literally named "vape", `WurstClient.jar` matched on the same
path keyword. Players who renamed `atermys loader.exe` to
`Anydesk.exe` (or repacked a Doomsday jar with scrambled
class names) walked straight past v0.9.2. v0.9.3 closes that
hole with a content-based detector that ignores file names.

### Added

- **`CheatFingerprints`** — first-class data table of known cheat
  fingerprints. Two complementary tiers:
  - `KnownCheatHashes` — full-file SHA-256 lookups for cheat builds
    confirmed in the wild (Atermys Client loader, Doomsday Client
    jar, Slinky.gg crack zip + loader). Survives renames /
    re-icons / re-signing.
  - `BinaryMarkers` — distinctive ASCII / UTF-16-LE substrings
    inside the binary (PDB paths, RTTI export names, branding
    banners, log strings, channel URLs). Catches re-built /
    repacked variants that don't share the bootstrap hash. Ships
    seed entries for **Atermys, Slinky.gg, Doomsday, Wurst,
    Sigma, Impact, LiquidBounce, RusherHack, Vape, Aristois,
    Salhack, Konas, Wolfram, BleachHack, Future, Phobos, Moon,
    Celestial, Kosen, plus generic loader / injector strings**.
- **`BinaryMarkerScanner`** utility — reads up to 8 MB of a file
  and runs the marker list against the bytes treated as Latin-1
  (catches plain PE strings) and as UTF-16-LE (catches widechar
  resources / `.NET ldstr` literals). Per-pattern dedup keeps
  one marker hit per (cheat, variant) per file even when a
  pattern repeats.
- **`CheatExeScanner`** — walks the user-controlled folders
  (Desktop, Downloads, Documents, Public, AppData, LocalAppData,
  %TEMP%, profile root) and inspects every `.exe / .dll / .jar /
  .zip` ≤ 200 MB. Two passes per file:
  - SHA-256 → `KnownCheatHashes` lookup.
  - Raw-bytes → `BinaryMarkerScanner.Scan` (and, for archives,
    up to 64 entries each scanned with a 256 KB budget — catches
    cheat banners that only live inside one bootstrap class of a
    fat jar).
  Each match emits a single `Severity.Hit` card per (file, cheat)
  pair, tagged `cheat-exe` plus `hash-match` or `marker-match`.
- **`--no-exe-scan` CLI flag** — opt out of `CheatExeScanner` for
  staff who already triaged renamed-cheat files manually or who
  don't want the extra few seconds the file walk costs on a slow
  player machine.

### Changed

- `ScanOptions` gained `NoExeScan`. `ScanOrchestrator` runs
  `CheatExeScanner` directly after `HeuristicEngineScanner` so
  the renamed-cheat findings sit alongside the other
  content-based heuristics in the report.

### Compatibility

- No breaking changes. Existing flags work unchanged.
- The renamed-cheat detector is opt-out: omit `--no-exe-scan` to
  use it (default), pass it to skip.
- Findings are taggable / dedupe-able like every other scanner —
  a player whose `Anydesk.exe` is the renamed Atermys loader will
  collapse with the existing Process / Recent / Registry hits on
  the same `atermys` keyword.

## [0.9.2] — 2026-05

Quality-of-life fix for `BrowserHistoryScanner`. v0.9.1 reports
sometimes had ~10–20 separate "Cheat-client domain in browser
history" cards for one player (one per matched URL across one or
more browser profiles). v0.9.2 collapses them into **a single card
sorted newest-first**, matching the v0.9.1 jar-aggregation pattern.

### Changed

- **`BrowserHistoryScanner`** now emits at most **one** aggregated
  finding per scan, listing up to 25 most-recent visits to
  cheat-client domains across Chrome / Edge / Brave / Opera /
  Vivaldi / Firefox profiles. Older visits collapse into a
  `... and N more older visit(s)` line.
- Each row in the detail block is formatted as
  `YYYY-MM-DD HH:mm  [Browser / Profile]  url  -> matched-keywords  page-title`.
  Visits are sorted by `last_visit_time` descending so staff see
  the most recent activity first.
- Tags become the union of every distinct cheat-domain keyword
  that fired, so cross-source dedup with USN / Recent / Registry
  continues to work.

### Compatibility

- No flag changes; identical to v0.9.1 except for the report card
  layout. Console output still logs each match individually for
  triage, but the HTML report shows one aggregated card.

## [0.9.1] — 2026-05

Hotfix for `MinecraftScanner` jar-entry blow-up. The very first
v0.9.0 report from a tester returned **378 detects** because a
single fat cheat-client jar in `versions/` contained ~250 cheat-named
class entries — and v0.8.0's per-keyword report dedup couldn't merge
them because every entry carried a different cheat keyword (`esp`,
`scaffold`, `step`, `phase`, `regen`, …). v0.9.1 collapses these
into a single per-jar finding so the headline detect count actually
reflects the number of suspicious *files*, not the number of class
entries inside them.

### Changed

- **`MinecraftScanner.InspectJar`** now emits at most **two**
  aggregated findings per jar instead of one per matched zip entry:
  - `Suspicious entries inside jar` — aggregates all `InternalKeywords`
    matches into a single Hit, listing up to 12 sample entries
    (and "... and N more") in the detail.
  - `Cheat-named entries inside jar` — aggregates all `NameKeywords`
    matches the same way.
  Tags become the union of every distinct keyword that fired.
  A jar with 258 matched entries now produces 1 card, not 258.
- The `Hit` console output is also collapsed: instead of one line
  per entry, scanners log the aggregated count and keyword list.

### Compatibility

- No flag changes. CLI, scan order, and other scanners are
  unchanged. Existing `--no-discord` / `--recycle-window` flags
  work identically.
- Findings still carry the per-jar `FilePath` + sha256, so
  downstream Modrinth / VirusTotal lookups remain unaffected.

## [0.9.0] — 2026-05

Headline-readable verdict + JSON export + Discord account
attribution. Staff opening the HTML report wanted three things that
v0.8.x didn't give them: an immediate "is this player cheating?"
answer at the top of the page, a way to keep / share the report as
structured data, and the actual Discord account a player is signed
in to so cross-server reports can correlate.

### Added

- **Verdict banner** at the very top of the HTML report. One large
  line, colour-coded by the worst severity actually present:
  - `Detects > 0` → red **"This user is cheating (N detect[s])"**
  - `Warnings > 0` → yellow **"This user is suspicious (N warning[s])"**
  - otherwise → green **"This user looks clean (no detects)"**
  The banner sits above the existing severity-count cards and is the
  first thing visible on page load. No more skimming card counts to
  decide if a player passed.
- **Export button** in the report header (top-right). Pressing it
  downloads a `mcss-report-<host>-<timestamp>.json` file containing
  the full structured payload (counts, sections, findings, account
  info, Discord accounts). The JSON is embedded at render time as a
  `<script type="application/json">` tag, so the export works fully
  offline from the saved HTML file — no network calls, no server.
  Useful for archiving SS evidence or pasting into a staff-only
  triage doc.
- **`DiscordAccountScanner`** — reads Discord's
  `Local Storage\leveldb\` `_remoteAuth_recentAccounts` entries from
  the standard `%APPDATA%\discord` install plus the PTB / Canary
  variants and pulls out the *public* fields of each signed-in
  account: snowflake `userId`, `username`, optional `globalName`,
  optional `avatarHash`, and which client variant the account was
  found in. Falls back to the inline user objects in the redux state
  cache when the recent-accounts list isn't populated. **Read-only,
  public fields only — never reads tokens, DM contents, friend
  lists, or chat messages.**
- **Discord Accounts card** in the HTML report. Replaces the old
  generic "Discord installations" card when at least one signed-in
  account is found. Shows each account with its avatar (loaded from
  Discord's CDN), display name, `@username`, snowflake ID with a
  one-click copy button, and the client variant (Discord / PTB /
  Canary) for non-default installs. Falls back to the v0.8.x
  installation list when no account is signed in.
- **`--no-discord` CLI flag** — disables `DiscordAccountScanner` for
  staff who'd rather not pull leveldb on the player's machine. The
  Discord installation card still renders.

### Changed

- `SessionReport` gained a `DiscordAccounts` list. `AccountInfo.cs`
  gained a `DiscordAccount` record (`UserId`, `Username`,
  `GlobalName`, `AvatarHash`, `ClientVariant`).
- `ScanOptions` gained `NoDiscord`. `ScanOrchestrator` runs
  `DiscordAccountScanner` between the existing Discord-install scan
  and the rest of the pipeline when the flag is not set.
- `HtmlReportRenderer` was extended (no scanner code touched) to
  emit the verdict banner, the Export button, the embedded JSON
  payload, and the new Discord Accounts card; `BuildJsonPayload()`
  and `JsonStr()` (JSON-string escape with `<` → `\u003c` to avoid
  `</script>` injection) are new helpers.

### Compatibility

- Existing CLI surface unchanged. The new `--no-discord` flag is
  opt-out only; if it's not passed, the Discord scanner runs.
- Reports rendered by v0.9.0 are still standalone, single-file HTML
  with no external resources required. Avatar images load from the
  Discord CDN over HTTPS; the rest of the report (banner, JSON
  payload, Export button, the v0.8.x layout) works fully offline.

## [0.8.1] — 2026-05

Quality-of-life fix for the Recycle Bin scanner. Reports from staff
were complaining that this section took the longest of any scanner on
machines that hoard a full Recycle Bin (uninstall leftovers, app
updates, year-old downloads). For the screenshare cheat-detection use
case only the *recent* deletions matter — the suspicious behaviour is
"the player wiped a jar/exe just before the SS started", not "the
player has had a forgotten cheat in the trash since last summer".

### Changed

- **Recycle Bin scanner** now defaults to a **24-hour window**: only
  files whose `LastWriteTime` (which Windows uses as the deletion
  timestamp for `$Recycle.Bin/$R*` entries) is within the last 24 h
  are scanned for cheat keywords. Older entries are counted as
  "skipped" and don't run a keyword match. The section header now
  reads `Recycle Bin (jar / Minecraft files, deleted within last 24h)`
  and the final OK message reports `(N recent, M older skipped)` so
  staff can see at a glance how much was filtered.
- **Stat call optimised**. The per-file `new FileInfo(file)`
  allocation has been replaced with `File.GetLastWriteTime(file)` for
  the date check. `FileInfo` is only constructed for files that
  actually match a cheat keyword (to read `Length` for the report).
  On a 5 000-entry recycle bin this cuts the scanner's wall time
  roughly in half.

### Added

- **`--recycle-window <H>` flag.** Override the default 24-hour
  window: `--recycle-window 6` only looks at deletions within the
  last 6 hours, `--recycle-window 168` widens to a week. Pass
  **`--recycle-window 0`** to restore the v0.8.0 behaviour and scan
  every entry regardless of age.

### Compatibility

- No breaking changes. Tightening the default window is the only
  behaviour change vs. v0.8.0; if a staff member specifically wants
  the legacy full scan they can pass `--recycle-window 0`. All other
  flags work unchanged.

## [0.8.0] — 2026-05

The "less is more" release. The v0.7.0 report fired a card for every
prefetch / recent / USN entry it touched, which meant a healthy
machine still produced ~15 noisy cards (`WINWORD.EXE`, `ZALO.EXE`,
`UNINS000.EXE`, …). Same cheat hit from 3 scanners would also render
3 separate cards saying the same thing. v0.8.0 cuts that down without
losing any actual signal.

### Changed

- **Prefetch scanner** no longer emits an `Severity.Info` card for
  every `minecraft*` / `launcher*` / `java(w).exe-*` prefetch entry.
  Only entries whose name actually matches a cheat keyword now reach
  the report — everything else stays out.
- **Recent-files scanner** dropped the "Recently opened binary" Info
  pathway. We were flagging every `.lnk` shortcut to a `.jar` / `.exe`
  / `.bat` / `.cmd` / `.class` file as noise; now only shortcuts whose
  name matches a cheat keyword surface as Hits.
- **USN journal scanner** dropped the "Deleted binary on `<drive>`"
  per-file Warning pathway. Most deleted `.exe` files in NTFS journals
  are legitimate uninstalls (`UNINS000.EXE`) or app updates
  (`WINWORD.EXE`, `ZALO.EXE`); the noise was overwhelming. The
  `HeuristicEngineScanner.GenericSelfDestruct` heuristic still kicks
  in if the deletion count crosses its threshold (now read from
  `UsnJournalScanner.LastDeletedBinaryCount`), so mass-deletion
  behaviour is still flagged with one summary card.
- **Recycle Bin scanner** dropped the "Recycle Bin entry" per-file
  Info pathway for the same reason. Only matches against the cheat
  keyword list reach the report now.
- **HTML report — detect-card layout** is now compact: icon + status
  tag + title + path + Show details. The free-form "detect-desc"
  description block has been removed (most descriptions repeated the
  title), and the "row-meta" status blurb on compact rows
  ("Worth a closer look during the screenshare." etc.) has been
  removed. Staff already know what each severity means; the words
  were pure decoration.
- **HTML report — finding deduplication.** Findings that point at the
  same cheat client are now grouped into a single card, with the
  other sources collapsed into "Show details → Other source(s)".
  Grouping key is the first non-meta tag (the cheat keyword like
  `koid` / `atermys`); for findings without a keyword tag we fall
  back to `Source|Title`. A typical Atermys/Koid hit fired by
  Process+Recent+Registry now renders one card instead of three.
- **HTML report — severity filter** defaults to **HIT + WARN** only
  on a fresh install (existing `localStorage` preferences under
  `mcss-sev-filter` are still respected). The "Raw scanner sections
  (full log)" `<details>` block is also collapsed by default — open
  it only if you want the full per-section log.

### Internal

- `UsnJournalScanner` exposes `LastDeletedBinaryCount` so
  `HeuristicEngineScanner.GenericSelfDestruct` can tally deletions
  without scraping report sections.
- `HtmlReportRenderer` gained `SevRank()` / `DedupeKey()` helpers and
  a `MetaTags` set used to skip behaviour-tags (`active`, `recent-files`,
  `selfdestruct`, …) when computing the dedup key.
- The unused `StatusBlurb()` helper has been removed.

### Compatibility

- No flag changes. CLI surface is identical to v0.7.0; existing
  `--console` / `--no-vt` / `--html-path` / etc. flows work unchanged.

## [0.7.0] — 2026-05

### Added

- **Windows Forms GUI as default mode.** Double-clicking
  `McSsCheck.exe` now opens a real window (no more raw `cmd.exe`)
  with:
  - title bar + version label,
  - progress bar that animates while a scan is running and turns
    into a determinate `step / total` bar once the orchestrator
    knows how many sections will run,
  - status label showing the currently-active section,
  - severity-tinted colored log (HIT red / WARN yellow / OK green /
    INFO blue / Section yellow / Banner cyan) backed by a
    `RichTextBox`,
  - four buttons: **Start scan**, **Cancel**, **Open HTML report**,
    **Close**, with a state machine that enables/disables them based
    on the current phase (Idle / Running / Done / Cancelled / Failed).
- **Cancellation.** The Cancel button cancels the scan via a
  `CancellationTokenSource` plumbed through the orchestrator. Any
  in-flight scanner that respects the token (Modrinth, VirusTotal,
  …) bails out cleanly; the report still gets rendered with whatever
  was collected so far.
- **HTML report — severity filter bar.** The "Raw scanner sections
  (full log)" `<details>` block now has a sticky toolbar with five
  toggle buttons (**Hit / Warn / OK / Info / Err**) plus an **All**
  master toggle. Clicking a button hides every `<tr>` of that
  severity in every section. State is persisted to `localStorage`
  (key `mcss-sev-filter`) so a refresh keeps the staff member's
  view. The "Raw scanner sections" block also defaults to expanded
  now that filtering makes it useful.

### Changed

- **`OutputType`** flipped from `Exe` to `WinExe`. No more black
  console window flashing on launch.
- **Scanning logic extracted** from `Program.Main` into a reusable
  `ScanOrchestrator.RunAsync(ScanOptions, IProgressSink, CancellationToken)`.
  Both the GUI and the legacy `--console` host call into it — the
  scanner code is unchanged.
- **`ConsoleUI` is now a façade** over a swappable `IUiSink`. The
  default sink (`ConsoleUiSink`) is the old behaviour byte-for-byte;
  the GUI host installs `GuiUiSink` at startup so the same
  `ConsoleUI.Hit / .Warn / .Info` calls land in the WinForms log
  with the right colour.
- **Argument parsing**: added `--gui` (default; explicit form for
  scripting) and `--console` (legacy stdout streaming). Behaviour of
  every existing flag is unchanged.
- **`EnableWindowsTargeting`** added to the csproj so non-Windows
  CI / dev VMs can `dotnet build` the project for syntax checks.
  The actual binary is still produced by the Windows CI runner.

### Compatibility

- `--console` reproduces the v0.6.0 stdin/stdout flow exactly,
  including the `yes`-typed consent prompt and the "Press Enter to
  close" tail. SS staff workflows that screen-share the console can
  keep using `McSsCheck.exe --console`.
- All previous `--no-*`, `--vt-key`, `--html-path`, `-y`, `--report-only`
  flags work in both modes.

## [0.6.0] — 2026-05

### Added

- **`StartupFolderScanner`** — scans the per-user
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and the
  all-users `%ProgramData%\…\Startup` folders. `.lnk` shortcuts are
  resolved through `WScript.Shell` so the actual executable target is
  matched against the cheat keyword list — not just the shortcut name.
- **`ScheduledTaskScanner`** — walks `%SystemRoot%\System32\Tasks`,
  parses each task XML, and matches the task name + every
  `<Exec><Command>` / `<Arguments>` / `<WorkingDirectory>` against
  cheat keywords. Tasks that run a `.jar` or run anything from a temp /
  downloads folder are flagged as `WARN` even when they don't match a
  keyword. Read-only — never invokes a mutating `schtasks` verb.
- **`RecentFilesScanner`** — scans
  `%APPDATA%\Microsoft\Windows\Recent\*.lnk`, sorted newest-first. Useful
  catch-all for cheat jars / installers that the player deleted before
  the screenshare but didn't clear from Recent.
- **External cheat-loader process detection** — `ProcessScanner` now
  enumerates every running process (not just `java(w).exe`) and matches
  the names against `KnownCheats.ExternalCheatProcessNames`. Detects
  Vape v4, Doomsday, Sigma external, atomic-loader, fdp-loader,
  nighthawk-loader, sky-loader, rapid-loader, tomate-loader,
  schizoid-loader, ghost-loader, and more.
- **`KnownCheats.MatchProcessName`** — token-boundary matcher used by
  the loader scan. Requires the cheat keyword to be flanked by
  non-letter chars / string boundaries, so "ares" no longer matches
  "share".
- **`KnownCheats.WellKnownBenignProcesses`** — allowlist of common
  legitimate processes (Discord, Spotify, Steam, javaw, Chrome,
  Firefox, MSTeams, Slack, OBS, Minecraft launchers, …) so the loader
  scan never reports a HIT on them.
- **HTML report**: scan duration is now shown in the header next to
  the Started / Finished timestamps.

### Changed

- **Centralised version string.** The version is now read at startup
  from the assembly's `InformationalVersion` attribute. Bumping the
  version only requires editing `McSsCheck.csproj` — the value
  automatically flows into:
  - the on-screen "v0.6.0" line of the consent banner
  - the HTML report header
  - the `User-Agent` of the Modrinth client (was hard-coded `0.3.0`)
  - the `User-Agent` of the VirusTotal client (was hard-coded `0.2.0`)
- **Cheat database expanded** (`Data/KnownCheats.cs`):
  - `NameKeywords` — ~40 new entries (auto32k / fdpclient /
    atomic-loader / spirit-client / nighthawk / sky-client / polywrap /
    hexware-loader / crystalware / ghosthack / blackbox-client / zoot /
    syrup-client / tomate-client / ronin-client / kosen-client /
    trex-client / verge-client / rapid-client / lunar-cheat /
    feather-cheat / badlion-cheat / essential-cheat / schizoid /
    rosehip / x-ray-mod / world-downloader / …).
  - `CheatDomains` — ~25 new entries (alpine-client.com /
    expensive-client.org / future.nl / moho-client.com / drowned.gg /
    matrix.vg / hexware.io / sigmajek.cc / ghost-client.cc /
    killaura.gg / fdpclient.com / nightclient.cc / skyclient.cc /
    rapidclient.org / tomateclient.com / rosehipclient.com /
    schizoidclient.com / and several GitHub mirrors).
  - `InternalKeywords` — ~15 new entries (sneakaura / anti-aim /
    auto-fish / ghosthand / block-esp / tnt-aura / auto-place /
    auto-disconnect / `modules/exploit/` / `modules/world/` /
    `modules/player/` / `obfuscated/aaaa` / `cheat/module` …).
  - `ExternalCheatProcessNames` — ~15 new entries (atomicloader /
    spiritloader / fdploader / nighthawkloader / skyloader /
    rapidloader / tomateloader / schizoidloader / ghostloader …).

### Fixed

- `UsnJournalScanner.Scan(...)` had an unused local `pages` that broke
  `dotnet build --warnaserror`. Removed.
- HTTP `User-Agent` strings on `ModrinthChecker` and `VirusTotalChecker`
  were stuck at `McSsCheck/0.3.0` and `McSsCheck/0.2.0`. Both now use
  the live tool version.
- `SessionReport.ToolVersion` was a hard-coded constant; it is now a
  writable property filled at startup so renderers always show what
  the running binary actually is.

## [0.5.0]

Initial public release in this repository — see commit history.
