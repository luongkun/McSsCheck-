# McSsCheck

A small Windows tool that helps server staff run a **consensual** Minecraft
screenshare (SS) session: it inspects the local machine for well-known
Minecraft Java cheat-client artifacts and writes a report — to a colored
window with a progress bar, and to a self-contained HTML file in the
user's `%TEMP%` folder. A legacy `--console` mode is still shipped for
SS workflows that prefer streaming stdout.

> **This is a forensic helper, not a verdict.** Every `[HIT]` line should be
> reviewed with the player. Cheat-client *names* and *domains* show up in
> screenshots, blog posts, and YouTube videos all the time — context matters.

## What it scans

- **PC information** (new in v0.3.0) — Windows version + build, last
  boot time, install date, locale / country, CPU / GPU / RAM / disks,
  last `javaw.exe` / Minecraft launcher prefetch entry, last write time
  inside `$Recycle.Bin`, **VPN heuristic** (TAP-Windows / WireGuard /
  OpenVPN / NordVPN / etc. adapters and services), and Discord install
  presence (variant + version + running). The Discord check **only**
  looks at the install folder; it never opens leveldb / chats / tokens.
- **Running `java.exe` / `javaw.exe` processes** — command line (incl. JVM
  args like `-javaagent:`), loaded DLLs, jars on the cmdline.
- **`%APPDATA%\.minecraft`** — `mods/`, `versions/`, `launcher_profiles.json`,
  `resourcepacks/`. Hashes (SHA-256 + SHA-1) every jar, flags filenames and
  internal entries that match known cheat keywords, and runs a **packed-jar
  heuristic** (Shannon entropy + ProGuard/Allatori/Stringer/Zelix markers
  + ratio of 1–2 character class names).
- **Mod registry verification (Modrinth)** (new in v0.3.0) — submits the
  SHA-1 of every mod jar to the public [Modrinth](https://modrinth.com)
  API in a single batch. Recognised jars are tagged **VERIFIED** with the
  registry project / download URL; unknown jars are tagged **NOT
  VERIFIED** for staff to look at more carefully. **Hashes only — never
  the file.** Disable with `--no-modrinth`.
- **Alternative Minecraft accounts** (new in v0.3.0) — parses launcher
  profile files for vanilla launcher, TLauncher, Lunar Client, Feather
  Client, Badlion Client, Prism / MultiMC. Only username / UUID / type
  are extracted — **no auth tokens**.
- **`$Recycle.Bin`** — only `.jar`, `.exe`, `.bat`, `.class` files.
- **`C:\Windows\Prefetch`** — only entries that start with `java.exe-`,
  `javaw.exe-`, or contain `minecraft`/`launcher`.
- **HKCU registry**: `MUICache`, `Run`/`RunOnce`, `OpenSavePidlMRU\jar`.
- **Browser history** (Chrome / Edge / Brave / Opera / Vivaldi / Firefox) —
  matches each URL against a hardcoded list of cheat-client domains
  (e.g. `wurstclient.net`, `meteorclient.com`, …). Does not read any other
  browser data.
- **Startup folder** (new in v0.6.0) — scans the per-user
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` and the
  all-users equivalent for `.lnk` / `.bat` / `.jar` / `.vbs` / `.ps1`
  entries that auto-run at login. `.lnk` shortcuts are resolved through
  `WScript.Shell` so the underlying executable is matched, not just the
  shortcut filename.
- **Scheduled tasks** (new in v0.6.0) — walks `%SystemRoot%\System32\Tasks`
  and reads each on-disk task XML. Flags tasks whose name, command,
  arguments or working directory match cheat keywords, plus tasks that
  run a `.jar` or run anything from a temp/downloads folder. Read-only;
  nothing is created, modified, or scheduled.
- **Windows Recent shortcuts** (new in v0.6.0) — scans
  `%APPDATA%\Microsoft\Windows\Recent\*.lnk` for recently-opened files.
  Newest entries first; matches against cheat keywords and additionally
  surfaces every `.jar` / `.exe` / `.bat` / `.class` shortcut as `INFO`
  for staff to review. Useful when the player deleted the cheat jar but
  forgot to clear Recent.
- **External cheat-loader processes** (new in v0.6.0) — enumerates all
  running processes and matches their names against the standalone
  cheat-loader list (Vape v4, Doomsday, Sigma external, etc.) using
  token-boundary matching to avoid false positives.
- **NTFS USN journal (admin only)** — lists recently *deleted* `.jar` /
  `.exe` / `.bat` / `.class` filenames the player wiped before the SS.
- **Windows Defender history** — events `1006`, `1007`, `1015`, `1116`, `1117`
  in `Microsoft-Windows-Windows Defender/Operational` plus the on-disk
  `DetectionHistory` files. Surfaces malware detections that mention
  Java / Minecraft / cheat keywords.
- **VirusTotal (optional)** — when a key is supplied, looks up the SHA-256
  of every `.minecraft` jar against the public VT v3 API. **Only the hash
  is sent — never the file**, and the step is rate-limited and capped per
  session. No key → step is skipped entirely.

The HTML report groups every result into Ocean-style buckets: **Detects**
(`HIT` rows), **Integrity** (`OK` rows from passed checks), **Warnings**
(`WARN`), **Suspicious** (`INFO` worth a look) and **Backstage** (entries
explicitly tagged `backstage`).

## What it does NOT do

- **Minimal network traffic, all opt-out.** By default the only outbound
  calls are the **Modrinth hash verification** (keyless, hash-only;
  disable with `--no-modrinth`) and the **optional VirusTotal lookup**
  (requires `--vt-key`; disable with `--no-vt`).
- **No telemetry, no upload, no exfiltration.**
- **No persistence**, no autostart, no scheduled task, no service install.
- **No reading** of passwords, saved logins, cookies, sessions, documents,
  crypto wallets, Discord tokens, etc.
- **No memory dump** of arbitrary processes; no driver, no kernel work.
- **No privilege escalation.** Some sources (USN journal, Defender event
  log, Prefetch on locked-down systems) are simply skipped if the tool
  isn't elevated.
- **No file writes** other than the HTML report under the user's `%TEMP%`
  folder. The report can be disabled with `--no-html`.

The full source is right here in this repo. Read it before you run it.

## How a screenshare session typically uses this

1. Player joins voice and shares their **whole desktop** in Discord.
2. Staff sends `McSsCheck.exe` to the player. Player saves it somewhere
   visible (e.g. Desktop) and runs it from a normal Command Prompt or
   PowerShell window so the player can see the output too.
3. Player types `yes` at the consent prompt.
4. Tool runs all enabled modules, prints the live console report, and at the
   end opens a colored HTML report in the player's default browser.
5. Both parties read the report together. Any `[HIT]` row is a conversation
   starter, not a verdict.
6. When done, the player can close the console, close the report tab and
   delete the .exe and the report file.

For better coverage of the "Recovery" and "Antivirus" sections, ask the
player to right-click `McSsCheck.exe` → **Run as administrator**. The tool
still works fine without it; those sections will simply log a clear
"skipped (not elevated)" entry.

## Building from source

Requires **.NET 8 SDK**.

```bash
# Restore + compile
dotnet build -c Release

# Single-file, self-contained Windows x64 .exe
dotnet publish -c Release -r win-x64 -o publish
# -> publish/McSsCheck.exe (~36 MB, no .NET runtime install required)
```

## Usage

```
McSsCheck.exe                       # GUI mode (default) — opens a window with a
                                    # progress bar, colored log and "Start scan"
                                    # / "Cancel" / "Open HTML report" buttons.
McSsCheck.exe --console             # legacy stdin/stdout console mode
McSsCheck.exe --console -y          # console mode, skip consent prompt
McSsCheck.exe --no-pcinfo           # skip PC information panel
McSsCheck.exe --no-accounts         # skip alternative Minecraft account scan
McSsCheck.exe --no-modrinth         # skip Modrinth jar verification (offline mode)
McSsCheck.exe --no-browser          # skip browser history scan
McSsCheck.exe --no-startup          # skip Startup folder scan
McSsCheck.exe --no-tasks            # skip Scheduled Task scan
McSsCheck.exe --no-recent           # skip Recent files scan
McSsCheck.exe --no-recycle          # skip Recycle Bin scan
McSsCheck.exe --no-registry         # skip registry scan
McSsCheck.exe --no-prefetch         # skip Prefetch scan
McSsCheck.exe --no-usn              # skip NTFS USN journal scan
McSsCheck.exe --no-defender         # skip Defender event log + DetectionHistory
McSsCheck.exe --no-vt               # skip VirusTotal hash lookups
McSsCheck.exe --no-html             # do not generate / open HTML report
McSsCheck.exe --report-only         # do not pause for Enter at end
McSsCheck.exe --vt-key <KEY>        # VirusTotal v3 API key (alt: VT_API_KEY env)
McSsCheck.exe --html-path <PATH>    # write HTML report to a specific file
McSsCheck.exe --no-exe-scan         # skip cheat-exe renamed-cheat hash/marker scan
McSsCheck.exe --no-agent-scan       # skip Java-agent manifest scan
McSsCheck.exe --help                # show all flags
```

### VirusTotal setup

1. Create a free account at <https://www.virustotal.com> and copy your
   personal API key from your profile page.
2. Either pass it on the command line:
   ```
   McSsCheck.exe --vt-key <YOUR_KEY>
   ```
   …or set the environment variable beforehand:
   ```
   set VT_API_KEY=<YOUR_KEY>
   McSsCheck.exe
   ```
3. The tool will hash every jar found under the player's `.minecraft`
   folder (SHA-256), then look those hashes up on VirusTotal. **Only
   the hash is sent — never the file**. Free-tier keys are limited to
   ~4 req/min and 500/day, so the tool throttles itself and caps at 24
   lookups per session.

## What's new in v0.9.5

- **New `JavaAgentScanner`.** Reads `META-INF/MANIFEST.MF` from
  every `.jar` in the scoped folders (`.minecraft/mods/`, `versions/`,
  Desktop, Downloads, Documents, Public, AppData, LocalAppData,
  %TEMP%, profile root) and flags jars that declare
  `Premain-Class` or `Agent-Class`. Legitimate Minecraft mods never
  declare a JVM-level Java agent — every cheat-agent family does
  (Doomsday, Weave, Koid, rebuilt Atermys, …). Catches renamed /
  repacked cheat agents that filename-based scanners miss. Disable
  with `--no-agent-scan`.
- **Cheat database expanded** — ~25 new client keywords covering
  2025-2026 clients (Koid, Atermys, Slinky.gg / Pluto Solutions,
  Orion, Zenith, Vivid, Solaris, Trident, Nexus, Astrolabe, Venom,
  Mistral, Raptor, Inferno, Polaris, Eclipse, Obsidian, Titan,
  Thunder), ~18 new distribution domains, new Java-agent package-path
  fragments (`net/java/f/`, `dev/koid/`, `gg/slinky/`, …), and new
  binary markers for Koid / Weave / Orion / Zenith / extra Atermys
  and Slinky builds / Doomsday's `net.java.f` premain signature.
- **Internal tidy.** Tokenizer + user-folder list + manifest parser
  live in one helper class each (`Util/CmdlineTokenizer`,
  `Util/UserFolders`, `Util/JarManifestInspector`); the two-to-three
  scattered copies that existed in the scanner files have been
  deleted.

## What's new in v0.7.0

- **Windows Forms GUI as default mode.** Double-clicking
  `McSsCheck.exe` now opens a real window with a progress bar,
  colored severity-tinted log (HIT red / WARN yellow / OK green /
  INFO blue) and **Start / Cancel / Open HTML report / Close**
  buttons. No more black `cmd.exe` flash on launch.
- **Scan cancellation.** The Cancel button cleanly stops the
  current scan via a `CancellationToken`; the HTML report still
  gets rendered with whatever was collected so far.
- **HTML report — severity filter bar.** The "Raw scanner sections"
  block now has Hit / Warn / OK / Info / Err toggle buttons (plus
  an All master toggle); state is persisted in `localStorage`.
- **`--console` flag** — the legacy stdin/stdout mode is still
  available unchanged for staff workflows that screen-share the
  console output.
- **Internal refactor.** Scanning logic moved into a reusable
  `ScanOrchestrator` and `ConsoleUI` is now a façade over a
  swappable `IUiSink`, so both hosts share the same scanner code.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

## What's new in v0.6.0

- **Three new persistence-aware scanners**: `StartupFolderScanner`,
  `ScheduledTaskScanner`, `RecentFilesScanner`. They cover the three
  most common spots where a cheat loader leaves traces even after the
  jar itself is deleted.
- **External cheat-loader process detection** in `ProcessScanner` —
  matches every running process against ~30 standalone cheat-loader
  names (Vape v4, Doomsday, Sigma external, atomic-loader, …) using
  **token-boundary matching** so words like "share" no longer match
  "ares".
- **Massively expanded cheat database** — ~40 new client name keywords,
  ~25 new cheat domains, ~15 new internal-jar keywords, ~15 new
  external loader process names, plus a benign-process allowlist
  (Discord, Spotify, Steam, Chrome, Firefox, …) to suppress false
  positives.
- **Centralised version string** — version is now read from the
  assembly's `InformationalVersion` so the value in `McSsCheck.csproj`,
  the HTTP `User-Agent` of the Modrinth and VirusTotal clients, and the
  HTML report header can never drift apart again.
- **HTML report**: now shows scan duration in the header.
- **Build fix**: removed an unused local in `UsnJournalScanner` that
  blocked `dotnet build --warnaserror`.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

## What's new in v0.3.0

- **PC Information panel** — OS version, boot time, install date,
  locale / country, CPU / GPU / RAM / disks, last game launch, last
  Recycle Bin entry, VPN heuristic, Discord install presence.
- **Detection categorisation** — results are now grouped into
  Detects / Integrity / Warnings / Suspicious / Backstage (Ocean-style)
  in the HTML report, with per-category count tiles and collapsible
  detail lists.
- **Alternative Minecraft accounts** — discovers accounts from vanilla
  launcher, TLauncher, Lunar Client, Feather Client, Badlion Client,
  and Prism / MultiMC profile files.
- **Mod registry verification (Modrinth)** — batch SHA-1 lookup against
  Modrinth to tag each mod jar as VERIFIED or NOT VERIFIED.
- **VPN heuristic** — flags TAP-Windows, WireGuard, OpenVPN, NordVPN,
  ExpressVPN, and 10+ other VPN adapter / service names.
- **Discord install detection** — detects Discord / Canary / PTB /
  Development variants, version, and running status. Does NOT read
  tokens, leveldb, or chat data.

## What's new in v0.2.0

- **Recovery (NTFS USN journal)** — recovers recently deleted `.jar` /
  `.exe` / `.bat` / `.class` filenames so a quick "I cleared my Recycle
  Bin before the SS" no longer hides everything.
- **Antivirus history** — pulls Windows Defender malware events out of
  the event log and the on-disk `DetectionHistory` store.
- **Packed-jar heuristic** — flags jars that look obfuscated/packed
  (Shannon entropy of class entries + ProGuard / Allatori / Stringer /
  Zelix markers + ratio of 1–2 char class names).
- **VirusTotal hash lookups** — optional, hash-only, opt-in via key.
- **HTML report** — a clean local report file that opens automatically
  in the default browser at the end of the scan.

## Limitations / honest caveats

- **It only finds things people forgot to clean up.** A motivated cheater
  who reformatted their drive yesterday will look clean. SS is one signal,
  not the only one — combine with server-side anti-cheat (Grim, Vulcan,
  NoCheatPlus, etc.) and replay analysis.
- The keyword list is intentionally substring-based and somewhat noisy.
  Expect false positives on words like `flux` (a popular ECS framework) or
  `step` (any auto-jump mod). Use judgment.
- The packed-jar heuristic also lights up on legitimately-obfuscated
  software (e.g. some commercial mods). Treat it as "look more carefully",
  not "guilty".
- Cheat clients evolve. Keep `Data/KnownCheats.cs` up to date.

## License

MIT. See `LICENSE`.
