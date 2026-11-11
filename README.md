# DLL Injector

Python harness for a simple DLL injector, intended to be used for games on Steam.

```
python3 ./src/app.py
```

The list shows injectable `.exe` processes. Wine games are found through
`/proc` and keep their own prefix, so the injector runs in the same prefix as the
game and `LoadLibraryA` lands in the live process. Wine's own helpers
(`services.exe`, `explorer.exe`, ...) and Steam's are filtered out; use the
filter box for busy machines. Windows hosts fall back to `tasklist`.

## How it injects

`injector.exe` is a small freestanding x64 PE (`injector.c`, no CRT, kernel32
only). Per run it:

1. finds the target PID with `CreateToolhelp32Snapshot` (case-insensitive name),
2. opens it with `PROCESS_ALL_ACCESS`, writes the DLL path with
   `VirtualAllocEx` + `WriteProcessMemory`,
3. starts `LoadLibraryA` in a remote thread and waits for it.

It reads `INJ_TARGET`, `INJ_PAYLOAD` and `INJ_WAIT_MS` from the environment, so
any ordinary DLL with a `DllMain` works. The injector is rebuilt automatically
if `injector.exe` is missing or older than `injector.c` (needs `clang`,
`llvm-dlltool`, `lld-link`).

Exit codes: `0` success, `2` no target given, `3` target not running, `4` no
payload given, `12` LoadLibraryA could not be dispatched.

## Requirements / notes

- Target and DLL must be x64; the DLL's own dependencies must be resolvable in
  the target's prefix.
- Same user as the game; on Linux `/proc/<pid>/environ` must be readable.
- Proton games: prefix = `WINEPREFIX`, else `STEAM_COMPAT_DATA_PATH/pfx`; the
  wine client comes from the game's own PATH (protocol match with the running
  `wineserver`), falling back to the Proton build listed in `config_info`.
- Anti-cheat protected games will block `OpenProcess`; that is a game-side
  limitation, not an injector bug.
