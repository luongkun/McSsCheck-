# Changelog

All notable changes to **McSsCheck** are listed here. Format inspired by
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

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
