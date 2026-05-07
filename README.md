# McSsCheck

A small Windows console tool that helps server staff run a **consensual** Minecraft
screenshare (SS) session: it inspects the local machine for well-known
Minecraft Java cheat-client artifacts and prints a report to the console.

> **This is a forensic helper, not a verdict.** Every "[HIT]" line should be
> reviewed with the player. Cheat-client *names* and *domains* show up in
> screenshots, blog posts, and YouTube videos all the time — context matters.

## What it scans

- **Running `java.exe` / `javaw.exe` processes** — command line (incl. JVM args
  like `-javaagent:`), loaded DLLs, jars on the cmdline.
- **`%APPDATA%\.minecraft`** — `mods/`, `versions/`, `launcher_profiles.json`,
  `resourcepacks/`. Hashes (SHA-256) every jar; flags filenames and internal
  entries that match known cheat keywords.
- **`$Recycle.Bin`** — only `.jar`, `.exe`, `.bat`, `.class` files; flags ones
  matching cheat keywords.
- **`C:\Windows\Prefetch`** — only entries that start with `java.exe-`,
  `javaw.exe-`, or contain `minecraft`/`launcher`.
- **HKCU registry**: `MUICache`, `Run`/`RunOnce`,
  `OpenSavePidlMRU\jar` — flags entries pointing at cheat-name binaries or
  recent `.jar` file picker activity.
- **Browser history** (Chrome / Edge / Brave / Opera / Vivaldi / Firefox) —
  only checks each URL against a hardcoded list of cheat-client domains
  (e.g. `wurstclient.net`, `meteorclient.com`, …). Does not read any other
  browser data.

## What it does NOT do

- **No network traffic, no telemetry, no upload.** Output is local only.
- **No persistence**, no autostart, no scheduled task, no service install.
- **No reading** of passwords, saved logins, cookies, sessions, documents,
  crypto wallets, Discord tokens, etc.
- **No memory dump** of arbitrary processes; no driver, no kernel work.
- **No privilege escalation**. Some sources (e.g. Prefetch on locked-down
  systems) may simply be skipped if the user lacks permissions.

The full source is right here in this repo. Read it before you run it.

## How a screenshare session typically uses this

1. Player joins voice and shares their **whole desktop** in Discord.
2. Staff sends `McSsCheck.exe` to the player. Player saves it somewhere
   visible (e.g. Desktop) and runs it from a normal Command Prompt or
   PowerShell window so the player can see the output too.
3. Player types `yes` at the consent prompt.
4. Both parties read the report together. Any `[HIT]` line is a
   conversation starter, not a verdict.
5. When done, the player can close the console and delete the .exe.

## Building from source

Requires **.NET 8 SDK**.

```bash
# Restore + compile
dotnet build -c Release

# Single-file, self-contained Windows x64 .exe
dotnet publish -c Release -r win-x64 -o publish
# -> publish/McSsCheck.exe
```

The published binary is self-contained: the player does **not** need to
install .NET to run it.

## Usage

```
McSsCheck.exe                # interactive scan with consent prompt
McSsCheck.exe -y             # skip prompt (only for automated reruns)
McSsCheck.exe --no-browser   # skip browser history scan
McSsCheck.exe --help         # show all flags
```

Running as Administrator gives slightly better coverage (Prefetch on some
machines, modules of elevated processes), but the tool works fine without it.

## Limitations / honest caveats

- **It only finds things people forgot to clean up.** A motivated cheater
  who reformatted their drive yesterday will look clean. SS is one signal,
  not the only one — combine with server-side anti-cheat (Grim, Vulcan,
  NoCheatPlus, etc.) and replay analysis.
- The keyword list is intentionally substring-based and somewhat noisy.
  Expect false positives on words like `flux` (a popular ECS framework) or
  `step` (any auto-jump mod). Use judgment.
- Cheat clients evolve. Keep `Data/KnownCheats.cs` up to date.

## License

MIT. See `LICENSE`.
