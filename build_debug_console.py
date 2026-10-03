"""Self-contained diagnostic-only DebugEnhancer fork; build only on macOS.

--verify is a read-only offline check and also works on Windows.
Compilation or offline checks do not establish that console routing or GUI boot works.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import struct
import subprocess
import tempfile
import urllib.request
import zipfile

PRODUCT = "DebugConsoleFix"
VERSION = "0.1.0"
BUNDLE_ID = "org.local.experimental.DebugConsoleFix"
SDK_COMMIT = "3f750085caa17ec3a7880f11c11bf4f48cd6a164"
SDK_SHA256 = "f028466e8a18cae2e95724152f915a44afc6352a8a80ae3d85567c55b6c1d60d"
SDK_URL = f"https://codeload.github.com/acidanthera/MacKernelSDK/zip/{SDK_COMMIT}"
LILU_VERSION = "1.7.2"
LILU_SHA256 = "e95df95d82e8b151047abf359ecd9c853755c59293e19dfcc3907da8fbd8cf89"
LILU_URL = "https://github.com/acidanthera/Lilu/releases/download/1.7.2/Lilu-1.7.2-DEBUG.zip"
ROUTE_SYMBOLS = ("_vprintf", "_kdb_printf", "_kprintf", "_IOLog")
SOURCES = json.loads(r'''{
  "kern_dbgenhancer.hpp": "// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2019 lvs1974. All rights reserved.\n// Diagnostic-only adaptation of DebugEnhancer 1.1.1; see provenance.json.\n#ifndef console_fix_hpp\n#define console_fix_hpp\n\n#include <Headers/kern_patcher.hpp>\n\nclass DBGENH {\npublic:\n    bool init();\n\nprivate:\n    void processKernel(KernelPatcher &patcher);\n    static int kdb_printf(const char *fmt, ...);\n    static void kprintf(const char *fmt, ...);\n    static void IOLog(const char *fmt, ...);\n    using t_kern_vprintf = int (*)(const char *, va_list);\n    t_kern_vprintf kern_vprintf = nullptr;\n    bool processed = false;\n};\n#endif\n",
  "kern_dbgenhancer.cpp": "// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2019 lvs1974. All rights reserved.\n// Diagnostic-only adaptation of DebugEnhancer 1.1.1; see provenance.json.\n#include <Headers/kern_api.hpp>\n#include <Headers/kern_util.hpp>\n#include \"kern_dbgenhancer.hpp\"\n\nstatic DBGENH *callbackDBGENH = nullptr;\n\nbool DBGENH::init() {\n    callbackDBGENH = this;\n    lilu.onPatcherLoadForce([](void *, KernelPatcher &patcher) {\n        callbackDBGENH->processKernel(patcher);\n    }, this);\n    return true;\n}\n\nint DBGENH::kdb_printf(const char *fmt, ...) {\n    va_list ap;\n    va_start(ap, fmt);\n    callbackDBGENH->kern_vprintf(fmt, ap);\n    va_end(ap);\n    return 0;\n}\n\nvoid DBGENH::kprintf(const char *fmt, ...) {\n    va_list ap;\n    va_start(ap, fmt);\n    callbackDBGENH->kern_vprintf(fmt, ap);\n    va_end(ap);\n}\n\nvoid DBGENH::IOLog(const char *fmt, ...) {\n    va_list ap;\n    va_start(ap, fmt);\n    callbackDBGENH->kern_vprintf(fmt, ap);\n    va_end(ap);\n}\n\nvoid DBGENH::processKernel(KernelPatcher &patcher) {\n    if (processed) {\n        patcher.clearError();\n        return;\n    }\n    processed = true;\n    // This marker deliberately does not require -dbgenhdbg.\n    printf(\"DebugConsoleFix: diagnostic callback started\\n\");\n    kern_vprintf = reinterpret_cast<t_kern_vprintf>(\n        patcher.solveSymbol(KernelPatcher::KernelID, \"_vprintf\"));\n    if (!kern_vprintf) {\n        printf(\"DebugConsoleFix: _vprintf unresolved, error %d\\n\", patcher.getError());\n        patcher.clearError();\n        return;\n    }\n    patcher.clearError();\n\n    // Hibernation symbols are deliberately absent from this logging batch.\n    // No sleep hooks, global IOKit flags, message-buffer resizing or byte patches.\n    KernelPatcher::RouteRequest requests[] {\n        {\"_kdb_printf\", kdb_printf},\n        {\"_kprintf\", kprintf},\n        {\"_IOLog\", IOLog}\n    };\n    const bool route_iolog = checkKernelArgument(\"-dbgenhiolog\");\n    const size_t count = arrsize(requests) - (route_iolog ? 0 : 1);\n    // Resolve every required target before applying any of the routes.\n    for (size_t i = 0; i < count; ++i) {\n        if (!patcher.solveSymbol(KernelPatcher::KernelID, requests[i].symbol)) {\n            printf(\"DebugConsoleFix: %s unresolved, error %d\\n\",\n                   requests[i].symbol, patcher.getError());\n            patcher.clearError();\n            return;\n        }\n        patcher.clearError();\n    }\n    if (patcher.routeMultipleLong(KernelPatcher::KernelID, requests, count)) {\n        // Unconditional, directly visible console confirmation after success.\n        printf(\"DebugConsoleFix: CONSOLE ROUTING ACTIVE (kdb_printf+kprintf, IOLog=%u)\\n\",\n               route_iolog ? 1U : 0U);\n    } else {\n        printf(\"DebugConsoleFix: console routing FAILED, error %d\\n\", patcher.getError());\n    }\n    patcher.clearError();\n}\n",
  "kern_start.cpp": "// SPDX-License-Identifier: BSD-3-Clause\n// Copyright (c) 2019 lvs1974. All rights reserved.\n// Diagnostic-only adaptation of DebugEnhancer 1.1.1; see provenance.json.\n#include <Headers/plugin_start.hpp>\n#include <Headers/kern_api.hpp>\n#include \"kern_dbgenhancer.hpp\"\n\nstatic DBGENH dbgenh;\nstatic const char *bootargOff[] { \"-dbgenhoff\" };\nstatic const char *bootargDebug[] { \"-dbgenhdbg\" };\nstatic const char *bootargBeta[] { \"-dbgenhbeta\" };\n\nPluginConfiguration ADDPR(config) {\n    xStringify(PRODUCT_NAME),\n    parseModuleVersion(xStringify(MODULE_VERSION)),\n    LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery | LiluAPI::AllowSafeMode,\n    bootargOff, arrsize(bootargOff),\n    bootargDebug, arrsize(bootargDebug),\n    bootargBeta, arrsize(bootargBeta),\n    KernelVersion::Tahoe, KernelVersion::Tahoe,\n    []() { dbgenh.init(); }\n};\n",
  "module.cpp": "// SPDX-License-Identifier: BSD-3-Clause\n// Local kmod metadata and entry-point wiring for DebugConsoleFix.\n#include <mach/mach_types.h>\n#include <mach/kmod.h>\n\nextern \"C\" {\nextern kern_return_t _start(kmod_info_t *, void *);\nextern kern_return_t _stop(kmod_info_t *, void *);\nextern kern_return_t DebugConsoleFix_kern_start(kmod_info_t *, void *);\nextern kern_return_t DebugConsoleFix_kern_stop(kmod_info_t *, void *);\nKMOD_EXPLICIT_DECL(org.local.experimental.DebugConsoleFix, \"0.1.0\", _start, _stop)\n__attribute__((visibility(\"hidden\"))) kmod_start_func_t *_realmain = DebugConsoleFix_kern_start;\n__attribute__((visibility(\"hidden\"))) kmod_stop_func_t *_antimain = DebugConsoleFix_kern_stop;\n__attribute__((visibility(\"hidden\"))) int _kext_apple_cc = __APPLE_CC__;\n}\n",
  "Info.plist": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>CFBundleDevelopmentRegion</key><string>en</string>\n<key>CFBundleExecutable</key><string>DebugConsoleFix</string>\n<key>CFBundleIdentifier</key><string>org.local.experimental.DebugConsoleFix</string>\n<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n<key>CFBundleName</key><string>DebugConsoleFix</string>\n<key>CFBundlePackageType</key><string>KEXT</string>\n<key>CFBundleShortVersionString</key><string>0.1.0</string>\n<key>CFBundleVersion</key><string>0.1.0</string>\n<key>NSHumanReadableCopyright</key><string>Derived from DebugEnhancer 1.1.1, Copyright (c) 2019 lvs1974. See LICENSE-DEBUGENHANCER.txt.</string>\n<key>OSBundleRequired</key><string>Root</string>\n<key>OSBundleLibraries</key><dict>\n<key>as.vit9696.Lilu</key><string>1.7.2</string>\n<key>com.apple.kpi.bsd</key><string>12.0.0</string>\n<key>com.apple.kpi.dsep</key><string>12.0.0</string>\n<key>com.apple.kpi.iokit</key><string>12.0.0</string>\n<key>com.apple.kpi.libkern</key><string>12.0.0</string>\n<key>com.apple.kpi.mach</key><string>12.0.0</string>\n<key>com.apple.kpi.unsupported</key><string>12.0.0</string>\n</dict>\n<key>IOKitPersonalities</key><dict>\n<key>org.local.experimental.DebugConsoleFix</key><dict>\n<key>CFBundleIdentifier</key><string>org.local.experimental.DebugConsoleFix</string>\n<key>IOClass</key><string>DebugConsoleFix</string>\n<key>IOMatchCategory</key><string>DebugConsoleFix</string>\n<key>IOProviderClass</key><string>IOResources</string>\n<key>IOResourceMatch</key><string>IOKit</string>\n</dict></dict>\n</dict></plist>\n",
  "README.md": "# DebugConsoleFix 0.1.0\n\nDiagnostic-only fork of DebugEnhancer 1.1.1 for the current x86_64 Tahoe recovery.\nThis is not an RTX driver and does not add GPU acceleration or promise GUI boot.\n\nThe fork retains the original kdb_printf/kprintf and optional IOLog-to-vprintf\nrouting, while removing hibernation hooks, gIOKitDebug modifications, and message\nbuffer resizing. A missing unrelated hibernation symbol can therefore no longer\nabort the logging batch. Every logging target is resolved before routing.\n\nThe marker `DebugConsoleFix: CONSOLE ROUTING ACTIVE` is printed unconditionally\nafter the routing batch reports success. It is not evidence that the graphics\ndriver started. `-dbgenhiolog` retains its original meaning; `-dbgenhoff` disables\nthe plugin. The usual Lilu plugin debug/beta flags are preserved. The plugin\nsupports Tahoe only, including Installer/Recovery and safe mode.\n\nBuild on an Intel macOS runner with Apple clang and ld:\n\n```sh\npython3 build_debug_console.py\n```\n\nThe build script is self-contained and contains the reviewed source, metadata,\nlicenses and verifier. Its only downloads are hash-pinned MacKernelSDK and Lilu\n1.7.2 DEBUG. The artifact is `dist/DebugConsoleFix-UNTESTED.zip`.\n\nRead-only offline symbol audit against the actual recovery and current Lilu:\n\n```sh\npython3 build_debug_console.py --verify DebugConsoleFix.kext \\\n  --boot-kc BootKernelExtensions.kc --lilu Lilu.kext/Contents/MacOS/Lilu \\\n  --nm /path/to/llvm-nm\n```\n\nCompilation, format validation and symbol presence do not verify runtime\nrouting. Replace stock DebugEnhancer for a trial; do not load both plugins.\nNo operating-system image, recovery files, private video or hardware logs are\nincluded in the source or artifact.\n",
  "LICENSE-DEBUGENHANCER.txt": "Copyright (c) 2017, lvs1974\n\nAll rights reserved.\n\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n\n1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n\n2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n\n3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n",
  "LICENSE-LILU.txt": "Copyright (c) 2016-2018, vit9696\nAll rights reserved.\n\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n\n1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n\n2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n\n3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
}''')

PROVENANCE = {
    "UpstreamProject": "https://github.com/acidanthera/DebugEnhancer",
    "UpstreamTag": "1.1.1",
    "UpstreamCommit": "8792fba2b28e51599e45e1293de868a179563d3a",
    "UpstreamLoggerSHA256": "a231d2e184e7a96d61f7797aec6eb2029810fb2a33f5a076d81d1a0107bd3281",
    "UpstreamStartSHA256": "56cc609d6413330ecf252a83d187695e66465aabac247fe104a13a0b93a4226b",
    "UpstreamLicenseSHA256": "9ef9bc3812b1e479b33d940623482ae56de90282a04de9e1776b4f0b218471f4",
    "LiluVersion": LILU_VERSION,
    "LiluArchiveSHA256": LILU_SHA256,
    "LiluLicenseSHA256": "74c3ca48189b796b0d262866e67de8efba77a71516667ce68dc3a8f13c2a3c57",
    "MacKernelSDKCommit": SDK_COMMIT,
    "MacKernelSDKArchiveSHA256": SDK_SHA256,
    "Changes": [
        "Unique DebugConsoleFix product and bundle identifier",
        "Keep kdb_printf/kprintf and optional -dbgenhiolog IOLog redirects",
        "Pre-resolve all logging route targets and emit unconditional result markers",
        "Remove all hibernation hooks, global IOKit flags and message-buffer modifications",
        "Limit Lilu plugin kernel range to Tahoe"
    ],
    "GraphicsDriver": False,
    "GPUAcceleration": False,
    "RuntimeTested": False,
    "GUIBootVerified": False
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    return subprocess.run([str(a) for a in args], check=True, text=True,
                          capture_output=True).stdout.strip()


def check_format(data):
    """Strict thin x86_64 MH_KEXT_BUNDLE check with nlist and relocation bounds."""
    def require(ok, message):
        if not ok:
            raise ValueError(message)
    require(len(data) >= 32, "Truncated Mach-O header")
    magic, cpu, subtype, kind, count, command_bytes, flags, _ = struct.unpack_from("<IiiIIIII", data)
    require(magic == 0xFEEDFACF and cpu == 0x01000007, "Expected thin x86_64 Mach-O")
    require(kind == 11, "Expected MH_KEXT_BUNDLE")
    require(command_bytes <= len(data) - 32 and count <= command_bytes // 8,
            "Load command table outside file")
    forbidden = {0xC, 0xD, 0xE, 0x20, 0x22, 0x80000018, 0x8000001C,
                 0x8000001F, 0x80000022, 0x80000023, 0x80000028,
                 0x80000033, 0x80000034}
    sections, symtab = [], None
    dynamic_relocations, offset = 0, 32
    for _ in range(count):
        require(offset + 8 <= 32 + command_bytes, "Truncated load command")
        cmd, size = struct.unpack_from("<II", data, offset)
        require(size >= 8 and size % 8 == 0 and size <= 32 + command_bytes - offset,
                "Invalid load command")
        require(cmd not in forbidden, "User-space dyld command found")
        if cmd == 0x19:
            require(size >= 72, "Truncated segment")
            segment = struct.unpack_from("<II16sQQQQiiII", data, offset)
            require(segment[9] <= (size - 72) // 80, "Truncated section table")
            require(segment[5] <= len(data) and segment[6] <= len(data) - segment[5],
                    "Segment outside file")
            for index in range(segment[9]):
                sec = struct.unpack_from("<16s16sQQIIIIIIII", data, offset + 72 + index * 80)
                name = sec[0].split(b"\0", 1)[0].decode("ascii")
                sec_type = sec[8] & 0xFF
                require(sec_type not in (7, 8), "Lazy pointers or symbol stubs found")
                if sec_type not in (1, 12, 18):
                    require(sec[4] <= len(data) and sec[3] <= len(data) - sec[4],
                            "Section outside file")
                require(sec[6] <= len(data) and sec[7] <= (len(data) - sec[6]) // 8,
                        "Section relocation table outside file")
                sections.append({"Name": name, "Bytes": sec[3], "Relocations": sec[7]})
        elif cmd == 2:
            require(size == 24 and symtab is None, "Invalid symbol table command")
            symtab = struct.unpack_from("<IIII", data, offset + 8)
        elif cmd == 11:
            require(size == 80, "Invalid dynamic symbol table")
            dynamic = struct.unpack_from("<20I", data, offset)
            for roff, rcount in (dynamic[16:18], dynamic[18:20]):
                require(roff <= len(data) and rcount <= (len(data) - roff) // 8,
                        "Dynamic relocation table outside file")
                dynamic_relocations += rcount
        offset += size
    require(offset == 32 + command_bytes and symtab is not None, "Invalid load command table")
    sym_offset, sym_count, str_offset, str_size = symtab
    require(sym_offset <= len(data) and sym_count <= (len(data) - sym_offset) // 16,
            "Symbol table outside file")
    require(str_offset <= len(data) and str_size <= len(data) - str_offset,
            "String table outside file")
    strings, defined, imports = data[str_offset:str_offset + str_size], set(), set()
    for i in range(sym_count):
        str_index, typ, _, _, value = struct.unpack_from("<IBBHQ", data, sym_offset + i * 16)
        if typ & 0xE0:
            continue
        require(str_index < str_size, "Symbol name outside string table")
        end = strings.find(b"\0", str_index)
        require(end >= 0, "Unterminated symbol name")
        name = strings[str_index:end].decode("ascii")
        if typ & 0x0E == 0:
            require(value == 0, "Unresolved common symbol")
            if name:
                imports.add(name)
        elif typ & 0x0E in (2, 14):
            defined.add(name)
    required = {"_kmod_info", "__start", "__stop", "__realmain", "__antimain",
                "_DebugConsoleFix_kern_start", "_DebugConsoleFix_kern_stop"}
    require(required <= defined, "Missing kmod or Lilu plugin entry points")
    require(any(n.startswith("__ZTV") and PRODUCT in n for n in defined), "Missing plugin vtable")
    require(any(s["Name"] == "__mod_init_func" and s["Bytes"] >= 8 for s in sections),
            "Missing C++ module initialization")
    require(not imports or dynamic_relocations or any(s["Relocations"] for s in sections),
            "Imports without relocation tables")
    require(BUNDLE_ID.encode() in data, "Missing bundle identity in kmod metadata")
    require(b"CONSOLE ROUTING ACTIVE" in data and b"diagnostic callback started" in data,
            "Missing unconditional diagnostic markers")
    return {"Architecture": "x86_64", "MachOType": "MH_KEXT_BUNDLE",
            "CPUSubtype": subtype, "HeaderFlags": hex(flags), "Sections": sections,
            "DynamicRelocations": dynamic_relocations, "Imports": sorted(imports),
            "FormatChecksPassed": True, "RuntimeTested": False, "GUIBootVerified": False}


def nm_exports(nm, path):
    output = command([nm, "--defined-only", "--extern-only", path])
    return set(re.findall(r"^\s*[0-9a-fA-F]+\s+[A-Za-z]\s+(\S+)\s*$", output, re.M))


def verify(bundle, boot_kc=None, lilu=None, nm=None):
    if bundle.is_dir():
        binary = bundle / "Contents" / "MacOS" / PRODUCT
        info_data = (bundle / "Contents" / "Info.plist").read_bytes()
        info = plistlib.loads(info_data)
        if info.get("CFBundleIdentifier") != BUNDLE_ID or info.get("CFBundleExecutable") != PRODUCT:
            raise ValueError("Unexpected bundle identity or executable")
        if info.get("CFBundleVersion") != VERSION or info.get("OSBundleRequired") != "Root":
            raise ValueError("Unexpected bundle version or required stage")
        if info.get("OSBundleLibraries", {}).get("as.vit9696.Lilu") != LILU_VERSION:
            raise ValueError("Unexpected Lilu dependency")
    else:
        raise ValueError("--verify requires the extracted DebugConsoleFix.kext directory")
    data = binary.read_bytes()
    report = {"State": "FormatCheckedRuntimeUntested", "BinarySHA256": sha256(data),
              "BinaryBytes": len(data), "InfoSHA256": sha256(info_data),
              "Binary": check_format(data), "ImportsPresent": False,
              "RuntimeRouteTargetsPresent": False, "RuntimeTested": False,
              "ConsoleRoutingVerified": False, "GUIBootVerified": False}
    requested = (boot_kc, lilu, nm)
    if any(v is not None for v in requested) and not all(v is not None for v in requested):
        raise ValueError("Symbol audit requires --boot-kc, --lilu and --nm together")
    if boot_kc is not None:
        boot_exports, lilu_exports = nm_exports(nm, boot_kc), nm_exports(nm, lilu)
        imports = set(report["Binary"]["Imports"])
        from_lilu = imports & lilu_exports
        from_boot = (imports - from_lilu) & boot_exports
        missing = imports - from_lilu - from_boot
        missing_routes = set(ROUTE_SYMBOLS) - boot_exports
        report.update({"State": "OfflineImportsAndRouteTargetsPresentRuntimeUntested",
                       "BootKCSHA256": sha256(boot_kc.read_bytes()),
                       "LiluSHA256": sha256(lilu.read_bytes()),
                       "ImportsFromLilu": sorted(from_lilu), "ImportsFromBootKC": sorted(from_boot),
                       "MissingImports": sorted(missing), "MissingRouteTargets": sorted(missing_routes),
                       "ImportsPresent": not missing, "RuntimeRouteTargetsPresent": not missing_routes,
                       "Method": "Defined external nlist symbols from actual BootKC fileset and Lilu; presence only"})
        if missing or missing_routes:
            raise ValueError("Offline symbol audit failed: " + json.dumps(report, indent=2))
    return report


def download_extract(url, digest, target):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024 or sha256(data) != digest:
        raise ValueError("Dependency download digest or size mismatch: " + url)
    archive = target.with_suffix(".zip")
    archive.write_bytes(data)
    target.mkdir()
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > 5000 or sum(e.file_size for e in entries) > 96 * 1024 * 1024:
            raise ValueError("Oversized dependency archive")
        for entry in entries:
            relative = PurePosixPath(entry.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in entry.filename:
                raise ValueError("Unsafe dependency archive path")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Dependency archive symlinks are rejected")
        source.extractall(target)


def build():
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise SystemExit("Requires Intel macOS and Apple's compiler/linker; no kext was built.")
    root = Path(__file__).resolve().parent
    clang = command(["xcrun", "--find", "clang"])
    compiler_version = command([clang, "--version"])
    if "Apple clang" not in compiler_version:
        raise ValueError("Apple clang is required")
    linker = command(["xcrun", "--find", "ld"])
    resource = Path(command([clang, "-print-resource-dir"]))
    sdk_version = command(["xcrun", "--sdk", "macosx", "--show-sdk-version"])
    (root / "build").mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="console-apple-build-", dir=root / "build"))
    source_dir = staging / "source"
    source_dir.mkdir()
    source_manifest = {}
    for name, content in SOURCES.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
            raise ValueError("Invalid embedded source path")
        data = content.encode("utf-8")
        (source_dir / name).write_bytes(data)
        source_manifest[name] = sha256(data)
    provenance = dict(PROVENANCE, EmbeddedSourceSHA256=source_manifest)
    (source_dir / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    sdk_root, lilu_root = staging / "sdk", staging / "lilu"
    download_extract(SDK_URL, SDK_SHA256, sdk_root)
    download_extract(LILU_URL, LILU_SHA256, lilu_root)
    sdk = sdk_root / ("MacKernelSDK-" + SDK_COMMIT)
    lilu = lilu_root / "Lilu.kext"
    resources = lilu / "Contents" / "Resources"
    flags = ["-target", "x86_64-apple-macos11.0", "-x", "c++", "-std=c++14",
             "-mkernel", "-fapple-kext", "-DKERNEL", "-DKERNEL_PRIVATE",
             "-DPRODUCT_NAME=DebugConsoleFix", "-DMODULE_VERSION=0.1.0", "-DDEBUG=1",
             "-O2", "-fno-rtti", "-fno-exceptions", "-fno-builtin", "-fno-stack-protector",
             "-fno-asynchronous-unwind-tables", "-mno-red-zone", "-fno-common", "-fvisibility=hidden",
             "-nostdinc", "-I", sdk / "Headers", "-I", resources,
             "-isystem", resource / "include", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-Wno-unknown-warning-option", "-Wno-ossharedptr-misuse"]
    objects = []
    for source in (source_dir / "kern_dbgenhancer.cpp", source_dir / "kern_start.cpp",
                   source_dir / "module.cpp", resources / "Library" / "plugin_start.cpp"):
        obj = staging / (source.stem + ".o")
        command([clang, *flags, "-c", source, "-o", obj])
        objects.append(obj)
    bundle = staging / (PRODUCT + ".kext")
    binary = bundle / "Contents" / "MacOS" / PRODUCT
    binary.parent.mkdir(parents=True)
    command([linker, "-kext", "-arch", "x86_64", "-platform_version", "macos", "11.0", sdk_version,
             "-undefined", "dynamic_lookup", "-o", binary, *objects,
             sdk / "Library" / "x86_64" / "libkmod.a"])
    (bundle / "Contents" / "Info.plist").write_bytes((source_dir / "Info.plist").read_bytes())
    report = verify(bundle)
    report.update({"State": "BuiltFormatCheckedUninstalled", "Compiler": compiler_version,
                   "AppleLinker": linker, "SDKVersion": sdk_version, "Provenance": provenance,
                   "BuildScriptSHA256": sha256(Path(__file__).read_bytes()),
                   "LiluBinarySHA256": sha256((lilu / "Contents" / "MacOS" / "Lilu").read_bytes())})
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    output = dist / "DebugConsoleFix-UNTESTED.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as result:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                result.write(path, path.relative_to(staging).as_posix())
        result.writestr("build-report.json", json.dumps(report, indent=2))
        result.writestr("provenance.json", json.dumps(provenance, indent=2))
        for path in sorted(source_dir.iterdir()):
            result.write(path, "source/" + path.name)
        result.write(Path(__file__), "source/build_debug_console.py")
    print(json.dumps({"Artifact": str(output), "ArtifactSHA256": sha256(output.read_bytes()),
                      "BinarySHA256": report["BinarySHA256"], "State": report["State"],
                      "RuntimeTested": False, "GUIBootVerified": False}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path, help="Extracted DebugConsoleFix.kext; read-only")
    parser.add_argument("--boot-kc", type=Path)
    parser.add_argument("--lilu", type=Path)
    parser.add_argument("--nm", type=Path)
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify(args.verify, args.boot_kc, args.lilu, args.nm), indent=2))
    elif any((args.boot_kc, args.lilu, args.nm)):
        parser.error("Offline audit options require --verify")
    else:
        build()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or "")
        print(error.stderr or "")
        raise SystemExit(error.returncode)
