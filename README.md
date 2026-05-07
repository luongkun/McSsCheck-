# McSsCheck

A small Windows console tool that helps server staff run a **consensual** Minecraft
screenshare (SS) session: it inspects the local machine for well-known
Minecraft Java cheat-client artifacts and prints a report — both to the
console and as a self-contained HTML file in the user's `%TEMP%` folder.

> **This is a forensic helper, not a verdict.** Every `[HIT]` line should be
> reviewed with the player. Cheat-client *names* and *domains* show up in
> screenshots, blog posts, and YouTube videos all the time — context matters.

## What it scans

- **Running `java.exe` / `javaw.exe` processes** — command line (incl. JVM
  args like `-javaagent:`), loaded DLLs, jars on the cmdline.
- **`%APPDATA%\.minecraft`** — `mods/`, `versions/`, `launcher_profiles.json`,
  `resourcepacks/`. Hashes (SHA-256) every jar, flags filenames and internal
  entries that match known cheat keywords, and runs a **packed-jar heuristic**
  (Shannon entropy + ProGuard/Allatori/Stringer/Zelix markers + ratio of
  1–2 character class names).
- **`$Recycle.Bin`** — only `.jar`, `.exe`, `.bat`, `.class` files.
- **`C:\Windows\Prefetch`** — only entries that start with `java.exe-`,
  `javaw.exe-`, or contain `minecraft`/`launcher`.
- **HKCU registry**: `MUICache`, `Run`/`RunOnce`, `OpenSavePidlMRU\jar`.
- **Browser history** (Chrome / Edge / Brave / Opera / Vivaldi / Firefox) —
  matches each URL against a hardcoded list of cheat-client domains
  (e.g. `wurstclient.net`, `meteorclient.com`, …). Does not read any other
  browser data.
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

## What it does NOT do

- **No network traffic by default.** The only outbound traffic possible
  is the optional VirusTotal hash lookup, which requires the staff member
  to explicitly pass `--vt-key` (or `VT_API_KEY`). Disable it any time
  with `--no-vt`.
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
McSsCheck.exe                       # interactive scan with consent prompt
McSsCheck.exe -y                    # skip prompt (only for automated reruns)
McSsCheck.exe --no-browser          # skip browser history scan
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
