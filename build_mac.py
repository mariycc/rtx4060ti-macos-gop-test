"""Build an uninstalled experimental kext with Apple tools on macOS only."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import plistlib
import subprocess
import tempfile
import urllib.request
import zipfile

from verify_kext import check

SDK_COMMIT = "3f750085caa17ec3a7880f11c11bf4f48cd6a164"
SDK_ARCHIVE_SHA256 = "f028466e8a18cae2e95724152f915a44afc6352a8a80ae3d85567c55b6c1d60d"
SDK_URL = f"https://codeload.github.com/acidanthera/MacKernelSDK/zip/{SDK_COMMIT}"


def command(args):
    return subprocess.run([str(arg) for arg in args], check=True,
                          text=True, capture_output=True).stdout.strip()


def main():
    if platform.system() != "Darwin":
        raise SystemExit("Requires Apple's macOS compiler and kext linker; no driver was built.")
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "source-manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["Files"].items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid source manifest path")
        actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Source digest mismatch: {name}")
    clang = command(["xcrun", "--find", "clang"])
    clang_version = command([clang, "--version"])
    if "Apple clang" not in clang_version:
        raise ValueError("An Apple compiler is required")
    linker = command(["xcrun", "--find", "ld"])
    resource = Path(command([clang, "-print-resource-dir"]))
    sdk_version = command(["xcrun", "--sdk", "macosx", "--show-sdk-version"])
    (root / "build").mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="apple-build-", dir=root / "build"))
    print(f"Build staging: {staging}", flush=True)
    archive = staging / "MacKernelSDK.zip"
    with urllib.request.urlopen(SDK_URL, timeout=60) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != SDK_ARCHIVE_SHA256:
        raise ValueError("MacKernelSDK archive digest mismatch")
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as source_zip:
        for entry in source_zip.infolist():
            relative = PurePosixPath(entry.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in entry.filename:
                raise ValueError("Unsafe SDK archive path")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("SDK symlinks are not accepted")
        source_zip.extractall(staging)
    sdk = staging / f"MacKernelSDK-{SDK_COMMIT}"
    flags = ["-target", "x86_64-apple-macos11.0", "-x", "c++", "-std=c++14",
             "-mkernel", "-fapple-kext", "-DKERNEL", "-DKERNEL_PRIVATE", "-O2",
             "-fno-rtti", "-fno-exceptions", "-fno-builtin", "-fno-stack-protector",
             "-fno-asynchronous-unwind-tables", "-mno-red-zone", "-fno-common",
             "-nostdinc", "-I", sdk / "Headers", "-isystem", resource / "include",
             "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"]
    objects = []
    for source in ("NVGopFramebuffer.cpp", "module.cpp"):
        obj = staging / (Path(source).stem + ".o")
        command([clang, *flags, "-c", root / source, "-o", obj])
        objects.append(obj)
    bundle = staging / "NVGopFramebuffer2803.kext"
    binary = bundle / "Contents" / "MacOS" / "NVGopFramebuffer"
    binary.parent.mkdir(parents=True)
    command([linker, "-kext", "-arch", "x86_64", "-platform_version", "macos",
             "11.0", sdk_version, "-undefined", "dynamic_lookup", "-o", binary,
             *objects, sdk / "Library" / "x86_64" / "libkmod.a"])
    binary_report = check(binary.read_bytes(), "NVGopFramebuffer")
    info = (root / "Info.plist").read_bytes()
    parsed = plistlib.loads(info)
    if parsed["CFBundleIdentifier"] != "org.local.experimental.NVGopFramebuffer2803":
        raise ValueError("Unexpected bundle identity")
    (bundle / "Contents" / "Info.plist").write_bytes(info)
    report = {
        "State": "BuiltFormatCheckedUninstalled",
        "Compiler": clang_version, "AppleLinker": linker, "SDKVersion": sdk_version,
        "MacKernelSDKCommit": SDK_COMMIT, "MacKernelSDKArchiveSHA256": SDK_ARCHIVE_SHA256,
        "BinarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "SourceManifest": manifest, "Binary": binary_report,
    }
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    output = dist / "NVGopFramebuffer2803-UNTESTED.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as result:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                result.write(path, path.relative_to(staging).as_posix())
        result.writestr("build-report.json", json.dumps(report, indent=2))
        for name in ("LICENSE", "README.md", "README-RU.md", "provenance.json"):
            result.write(root / name, name)
    print(f"Built and checked file format: {output}")
    print("Kernel symbol resolution, loading, GUI boot and GPU acceleration are unverified.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or "")
        print(error.stderr or "")
        raise SystemExit(error.returncode)
