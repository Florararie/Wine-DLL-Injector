from __future__ import annotations

import os
import csv
import sys
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, field

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)



ROOT = Path(__file__).resolve().parent
INJECTOR_EXE = ROOT / "injector" / "injector.exe"
INJECTOR_SOURCE = ROOT / "injector" / "injector.c"
KERNEL32_DEF = ROOT / "injector" / "kernel32.def"
KERNEL32_LIB = ROOT / "injector" / "kernel32.lib"
INJECTOR_OBJ = ROOT / "injector" / "injector.obj"
IS_WINDOWS = os.name == "nt"


# Wine's own plumbing, never a game the user wants to inject into.
# Update as needed. This list is not exhaustive.
WINE_SYSTEM = {
    "services.exe",
    "winedevice.exe",
    "plugplay.exe",
    "rpcss.exe",
    "svchost.exe",
    "conhost.exe",
    "wineboot.exe",
    "explorer.exe",
    "start.exe",
    "cmd.exe",
    "rundll32.exe",
    "tabtip.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "steamerrorreporter.exe",
    "xalia.exe",
    "lsass.exe"
}



@dataclass
class Target:
    pid: int
    exe: str
    prefix: Path | None = None
    wine: str | None = None
    wine_paths: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.exe}   ·   pid {self.pid}"



# ------------------------------------------------------------------ discovery
def _read_environ(pid: str) -> dict[str, str]:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for item in raw.split(b"\0"):
        key, sep, value = item.partition(b"=")
        if sep:
            values[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return values



def _prefix_from_env(env: dict[str, str]) -> Path | None:
    candidate = env.get("WINEPREFIX")
    if not candidate and env.get("STEAM_COMPAT_DATA_PATH"):
        candidate = str(Path(env["STEAM_COMPAT_DATA_PATH"]) / "pfx")
    if not candidate:
        return None
    prefix = Path(candidate)
    return prefix if (prefix / "drive_c").is_dir() else None



def _proton_wine(prefix: Path) -> str | None:
    """Wine from the Proton build recorded for this compatdata entry."""
    try:
        lines = (prefix.parent / "config_info").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    for line in lines:
        if "compatibilitytools.d" not in line and "steamapps/common/Proton" not in line:
            continue
        tool = Path(line.split("/files/")[0])
        for name in ("wine", "wine64"):
            candidate = tool / "files" / "bin" / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None



def _wine_binary(env: dict[str, str], prefix: Path | None) -> tuple[str | None, list[str]]:
    """A wine client compatible with the prefix's running wineserver.

    Proton's wine must speak the same protocol version as the server already
    serving the prefix, so the target process's own PATH is preferred.
    """
    for entry in env.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        for name in ("wine", "wine64"):
            candidate = Path(entry) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate), [entry]
    if prefix is not None:
        proton = _proton_wine(prefix)
        if proton:
            return proton, [str(Path(proton).parent)]
    wine = shutil.which("wine64") or shutil.which("wine")
    return wine, []



def wine_path(prefix: Path, path: Path) -> str:
    """Host path as the prefix's Windows namespace sees it."""
    resolved = Path(path).resolve()
    drive_c = (Path(prefix) / "drive_c").resolve()
    try:
        return "C:\\" + str(resolved.relative_to(drive_c)).replace("/", "\\")
    except ValueError:
        return "Z:" + str(resolved).replace("/", "\\")



def windows_processes() -> list[Target]:
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True
        )
    except OSError:
        return []
    found: list[Target] = []
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) < 2:
            continue
        image = row[0]
        if not image.lower().endswith(".exe") or image.lower() in WINE_SYSTEM:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        found.append(Target(pid=pid, exe=image))
    return found



def running_targets() -> list[Target]:
    """Every injectable .exe process, Wine/Proton ones with their prefix."""
    if IS_WINDOWS:
        return sorted(windows_processes(), key=lambda t: (t.exe.lower(), t.pid))
    found: list[Target] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return found
    for proc in proc_root.iterdir():
        if not proc.name.isdigit():
            continue
        try:
            raw = (proc / "cmdline").read_bytes()
        except OSError:
            continue
        args = [arg for arg in raw.split(b"\0") if arg]
        if not args:
            continue
        exe = args[0].decode("utf-8", "replace").replace("\\", "/").rsplit("/", 1)[-1]
        if not exe.lower().endswith(".exe") or exe.lower() in WINE_SYSTEM:
            continue
        env = _read_environ(proc.name)
        prefix = _prefix_from_env(env)
        if prefix is None:
            continue
        wine, paths = _wine_binary(env, prefix)
        found.append(
            Target(pid=int(proc.name), exe=exe, prefix=prefix, wine=wine, wine_paths=paths)
        )
    found.sort(key=lambda t: (t.exe.lower(), t.pid))
    return found



# ------------------------------------------------------------------- injector
def ensure_injector(emit) -> Path | None:
    """Return the compiled injector, rebuilding it with clang + lld if stale."""
    sources = [path for path in (INJECTOR_SOURCE, KERNEL32_DEF) if path.is_file()]
    if INJECTOR_EXE.is_file():
        built = INJECTOR_EXE.stat().st_mtime
        if all(source.stat().st_mtime <= built for source in sources):
            return INJECTOR_EXE
    clang = shutil.which("clang")
    dlltool = shutil.which("llvm-dlltool")
    linker = shutil.which("lld-link")
    missing = [
        name
        for name, found in (("clang", clang), ("llvm-dlltool", dlltool), ("lld-link", linker))
        if not found
    ]
    if missing or not INJECTOR_SOURCE.is_file() or not KERNEL32_DEF.is_file():
        emit(f"ERROR: cannot build injector (missing: {', '.join(missing) or 'sources'}).")
        return None
    emit("Building injector with clang/lld...")
    steps = [
        [dlltool, "-m", "i386:x86-64", "-d", str(KERNEL32_DEF), "-l", str(KERNEL32_LIB)],
        [
            clang,
            "--target=x86_64-pc-windows-msvc",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-O2",
            "-c",
            str(INJECTOR_SOURCE),
            "-o",
            str(INJECTOR_OBJ),
        ],
        [
            linker,
            "/nologo",
            "/subsystem:console",
            "/entry:inject_main",
            "/nodefaultlib",
            f"/out:{INJECTOR_EXE}",
            str(INJECTOR_OBJ),
            str(KERNEL32_LIB),
        ],
    ]
    for command in steps:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()[-3:]
            emit(f"ERROR: {Path(command[0]).name} failed: {' / '.join(detail)}")
            return None
    return INJECTOR_EXE if INJECTOR_EXE.is_file() else None



class InjectWorker(QThread):
    line = Signal(str)
    done = Signal(bool, str)

    def __init__(self, target: Target, dll: Path) -> None:
        super().__init__()
        self.target = target
        self.dll = dll

    def run(self) -> None:
        target, dll = self.target, self.dll
        self.line.emit(f"Target: {target.exe} (pid {target.pid})")
        self.line.emit(f"DLL: {dll}")
        if not dll.is_file():
            self.done.emit(False, "The selected DLL no longer exists.")
            return
        injector = ensure_injector(self.line.emit)
        if injector is None:
            self.done.emit(False, "The injector could not be built.")
            return

        env = dict(os.environ)
        env.update({"INJ_TARGET": target.exe, "INJ_WAIT_MS": "5000", "INJ_PAYLOAD": str(dll)})
        if IS_WINDOWS:
            command = [str(injector)]
            self.line.emit("Native Windows injection.")
        else:
            if target.prefix is None or target.wine is None:
                self.done.emit(False, "No Wine prefix/wine client for this process.")
                return
            self.line.emit(f"Prefix: {target.prefix}")
            self.line.emit(f"Wine: {target.wine}")
            env["WINEPREFIX"] = str(target.prefix)
            env["WINEDEBUG"] = "-all"
            env["INJ_PAYLOAD"] = wine_path(target.prefix, dll)
            if target.wine_paths:
                env["PATH"] = os.pathsep.join(target.wine_paths + [env.get("PATH", "")])
            command = [target.wine, str(injector)]
        self.line.emit(f"Payload path in target: {env['INJ_PAYLOAD']}")

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            self.done.emit(False, f"Could not run the injector: {exc}")
            return

        assert proc.stdout is not None
        for raw in proc.stdout:
            text = raw.rstrip()
            if not text or text.startswith("(lsfg-vk)"):
                continue
            self.line.emit(text)
            if self.isInterruptionRequested():
                proc.kill()
                break
        code = proc.wait()
        if code == 0:
            self.done.emit(True, f"Injected into {target.exe}.")
        else:
            self.done.emit(False, f"Injection failed (injector exit {code}).")




# ------------------------------------------------------------------------- UI
class InjectorWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DLL Injector")
        self.resize(750, 645)
        self.targets: list[Target] = []
        self.dll: Path | None = None
        self.worker: InjectWorker | None = None

        title = QLabel("DLL Injector")
        hint = QLabel("Select a running game process, choose a DLL, inject.")

        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter processes...")
        self.refresh_btn = QPushButton("Refresh")
        filter_row = QHBoxLayout()
        filter_row.addWidget(self.filter, 1)
        filter_row.addWidget(self.refresh_btn)

        self.processes = QListWidget()
        self.processes.setMinimumHeight(230)

        dll_label = QLabel("DLL")
        self.dll_path = QLineEdit()
        self.dll_path.setPlaceholderText("No DLL selected")
        self.dll_path.setReadOnly(True)
        browse = QPushButton("Browse...")
        dll_row = QHBoxLayout()
        dll_row.addWidget(self.dll_path, 1)
        dll_row.addWidget(browse)

        self.inject_btn = QPushButton("Inject")
        self.status = QLabel("")
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Injection output appears here.")
        inject_row = QHBoxLayout()
        inject_row.addWidget(self.inject_btn)
        inject_row.addWidget(self.status, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(9)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addLayout(filter_row)
        layout.addWidget(self.processes, 1)
        layout.addWidget(dll_label)
        layout.addLayout(dll_row)
        layout.addLayout(inject_row)
        layout.addWidget(self.log, 1)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

        self.refresh_btn.clicked.connect(self.refresh)
        self.filter.textChanged.connect(self._populate)
        self.processes.itemSelectionChanged.connect(self._selection_changed)
        browse.clicked.connect(self._browse)
        self.inject_btn.clicked.connect(self._inject)
        self.inject_btn.setEnabled(False)
        self.refresh()


    # -- process list -------------------------------------------------------
    def refresh(self) -> None:
        selected = self._current()
        selected_pid = selected.pid if selected else None
        self.targets = running_targets()
        self._populate()
        if selected_pid is not None:
            for row in range(self.processes.count()):
                target = self.targets[self.processes.item(row).data(Qt.UserRole)]
                if target.pid == selected_pid:
                    self.processes.setCurrentRow(row)
                    break
        self.status.setText(f"{len(self.targets)} injectable process(es) found.")


    def _populate(self) -> None:
        needle = self.filter.text().strip().lower()
        self.processes.blockSignals(True)
        self.processes.clear()
        for index, target in enumerate(self.targets):
            haystack = f"{target.exe} {target.pid} {target.prefix or ''}".lower()
            if needle and needle not in haystack:
                continue
            item = QListWidgetItem(target.label)
            item.setData(Qt.UserRole, index)
            if target.prefix:
                item.setToolTip(str(target.prefix))
            self.processes.addItem(item)
        self.processes.blockSignals(False)
        self._selection_changed()


    def _current(self) -> Target | None:
        item = self.processes.currentItem()
        if item is None:
            return None
        return self.targets[item.data(Qt.UserRole)]


    def _selection_changed(self) -> None:
        target = self._current()
        if target is not None:
            self.status.setText(
                f"{target.exe} (pid {target.pid})"
                + (f"\n{target.prefix}" if target.prefix else "")
            )
        self._update_inject()


    def _update_inject(self) -> None:
        busy = self.worker is not None and self.worker.isRunning()
        self.inject_btn.setEnabled(
            not busy and self._current() is not None and self.dll is not None
        )


    # -- dll / inject -------------------------------------------------------
    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a DLL", str(Path.home()), "DLL files (*.dll);;All files (*)"
        )
        if not path:
            return
        self.dll = Path(path)
        self.dll_path.setText(str(self.dll))
        self._update_inject()


    def _inject(self) -> None:
        target = self._current()
        if target is None or self.dll is None:
            return
        self.log.clear()
        self.inject_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self.worker = InjectWorker(target, self.dll)
        self.worker.line.connect(self.log.appendPlainText)
        self.worker.done.connect(self._finished)
        self.worker.start()


    def _finished(self, ok: bool, message: str) -> None:
        self.log.appendPlainText(("OK: " if ok else "FAILED: ") + message)
        self.status.setText(message)
        self.refresh_btn.setEnabled(True)
        self._update_inject()


    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self.worker.wait(3000)
        event.accept()



def main() -> int:
    app = QApplication(sys.argv)
    window = InjectorWindow()
    window.show()
    return app.exec()



if __name__ == "__main__":
    raise SystemExit(main())