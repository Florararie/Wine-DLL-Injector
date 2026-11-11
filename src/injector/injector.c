/* Generic x64 DLL injector — freestanding Windows PE (no CRT, kernel32 only).
 *
 * Build (see ensure_injector in app.py):
 *   llvm-dlltool -m i386:x86-64 -d kernel32.def -l kernel32.lib
 *   clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-builtin \
 *         -fno-stack-protector -O2 -c injector.c -o injector.obj
 *   lld-link /subsystem:console /entry:inject_main /nodefaultlib \
 *            /out:injector.exe injector.obj kernel32.lib
 *
 * Configuration comes from the environment so no CRT argument parsing is
 * needed:
 *   INJ_TARGET   target executable name, e.g. "ReadyOrNot-Win64-Shipping.exe"
 *   INJ_PAYLOAD  path to the DLL to load (as the target's prefix sees it)
 *   INJ_WAIT_MS  how long to wait for the process (default 30000)
 *
 * Injection is VirtualAllocEx + WriteProcessMemory of the DLL path followed by
 * CreateRemoteThread(LoadLibraryA).
 */
typedef unsigned long DWORD;
typedef unsigned long long ULONG_PTR;
typedef void *HANDLE;
typedef void *HMODULE;

#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define TH32CS_SNAPPROCESS 0x2
#define PROCESS_ALL_ACCESS 0x1F0FFF
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)

__declspec(dllimport) HANDLE __stdcall CreateToolhelp32Snapshot(DWORD, DWORD);
__declspec(dllimport) int __stdcall Process32First(HANDLE, void *);
__declspec(dllimport) int __stdcall Process32Next(HANDLE, void *);
__declspec(dllimport) int __stdcall CloseHandle(HANDLE);
__declspec(dllimport) HANDLE __stdcall OpenProcess(DWORD, int, DWORD);
__declspec(dllimport) void *__stdcall VirtualAllocEx(HANDLE, void *, ULONG_PTR, DWORD, DWORD);
__declspec(dllimport) int __stdcall WriteProcessMemory(HANDLE, void *, const void *, ULONG_PTR, ULONG_PTR *);
__declspec(dllimport) HANDLE __stdcall CreateRemoteThread(HANDLE, void *, ULONG_PTR, void *, void *, DWORD, DWORD *);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE, DWORD);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) int __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) DWORD __stdcall GetEnvironmentVariableA(const char *, char *, DWORD);
__declspec(dllimport) HMODULE __stdcall GetModuleHandleA(const char *);
__declspec(dllimport) void *__stdcall GetProcAddress(HMODULE, const char *);
__declspec(dllimport) void __stdcall Sleep(DWORD);
__declspec(dllimport) void __stdcall ExitProcess(DWORD);

typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    long pcPriClassBase;
    DWORD dwFlags;
    char szExeFile[260];
} PROCESSENTRY32A;

static unsigned long slen(const char *s) {
    unsigned long n = 0;
    while (s[n])
        n++;
    return n;
}

static void out(const char *s) {
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)slen(s), &written, 0);
}

static void out_num(unsigned long value, int hex) {
    char rev[32];
    const char *digits = "0123456789abcdef";
    char buf[33];
    int i = 0, j = 0;
    unsigned long base = hex ? 16 : 10;

    if (!value) {
        buf[0] = '0';
        buf[1] = 0;
        out(buf);
        return;
    }
    while (value) {
        rev[i++] = digits[value % base];
        value /= base;
    }
    while (i > 0)
        buf[j++] = rev[--i];
    buf[j] = 0;
    out(buf);
}

static int ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + 32);
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static DWORD find_pid(const char *exe) {
    PROCESSENTRY32A pe;
    HANDLE snap;
    DWORD pid = 0;
    int found;

    pe.dwSize = (DWORD)sizeof(pe);
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    found = Process32First(snap, &pe);
    while (found) {
        if (ieq(pe.szExeFile, exe)) {
            pid = pe.th32ProcessID;
            break;
        }
        found = Process32Next(snap, &pe);
    }
    CloseHandle(snap);
    return pid;
}

static unsigned long parse_uint(const char *s, unsigned long fallback) {
    unsigned long value = 0;
    int any = 0;
    while (*s >= '0' && *s <= '9') {
        value = value * 10 + (unsigned long)(*s - '0');
        s++;
        any = 1;
    }
    return any ? value : fallback;
}

static int load_library_into(DWORD pid, const char *dll_path) {
    HANDLE proc, thread;
    void *mem;
    ULONG_PTR written = 0;
    unsigned long length = slen(dll_path) + 1;
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    void *load_library = kernel ? GetProcAddress(kernel, "LoadLibraryA") : 0;

    if (!load_library) {
        out("ERROR: LoadLibraryA not resolvable\n");
        return 0;
    }
    proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!proc) {
        out("ERROR: OpenProcess failed (");
        out_num(GetLastError(), 0);
        out(")\n");
        return 0;
    }
    mem = VirtualAllocEx(proc, 0, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        out("ERROR: VirtualAllocEx failed (");
        out_num(GetLastError(), 0);
        out(")\n");
        CloseHandle(proc);
        return 0;
    }
    if (!WriteProcessMemory(proc, mem, dll_path, length, &written)) {
        out("ERROR: WriteProcessMemory failed (");
        out_num(GetLastError(), 0);
        out(")\n");
        CloseHandle(proc);
        return 0;
    }
    out("remote path at 0x");
    out_num((ULONG_PTR)mem, 1);
    out("\n");
    thread = CreateRemoteThread(proc, 0, 0, load_library, mem, 0, 0);
    if (!thread) {
        out("ERROR: CreateRemoteThread failed (");
        out_num(GetLastError(), 0);
        out(")\n");
        CloseHandle(proc);
        return 0;
    }
    WaitForSingleObject(thread, 15000);
    CloseHandle(thread);
    CloseHandle(proc);
    out("OK: LoadLibraryA dispatched\n");
    return 1;
}

void inject_main(void) {
    char payload[1024];
    char target[260];
    char wait_buf[24];
    DWORD pid = 0, wait_ms, waited;
    DWORD n;

    n = GetEnvironmentVariableA("INJ_TARGET", target, sizeof(target));
    if (n == 0 || n >= sizeof(target)) {
        out("ERROR: INJ_TARGET is not set\n");
        ExitProcess(2);
    }
    n = GetEnvironmentVariableA("INJ_PAYLOAD", payload, sizeof(payload));
    if (n == 0 || n >= sizeof(payload)) {
        out("ERROR: INJ_PAYLOAD is not set\n");
        ExitProcess(4);
    }
    wait_ms = 30000;
    n = GetEnvironmentVariableA("INJ_WAIT_MS", wait_buf, sizeof(wait_buf));
    if (n > 0 && n < sizeof(wait_buf)) {
        wait_buf[n] = 0;
        wait_ms = parse_uint(wait_buf, 30000);
    }

    for (waited = 0; waited <= wait_ms && !pid; waited += 500) {
        pid = find_pid(target);
        if (!pid)
            Sleep(500);
    }
    if (!pid) {
        out("ERROR: ");
        out(target);
        out(" is not running\n");
        ExitProcess(3);
    }
    out("target pid=");
    out_num(pid, 0);
    out("\n");

    ExitProcess(load_library_into(pid, payload) ? 0 : 12);
}
