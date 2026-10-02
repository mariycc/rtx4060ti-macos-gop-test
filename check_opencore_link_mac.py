"""Offline OpenCore linking experiment; never install or deploy its output."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import plistlib
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

OC_COMMIT = "6fe4d15cb66596d99d8cfedce69d8fc6dad71886"
OC_SHA256 = "0223d4edcf4a766a5ee6c12a5b19526ba6e43cdf276b189a2c16ca93721f6559"
AUDK_COMMIT = "bdbc1cd406d6085b7d10fa62df06ad24e84a4928"
AUDK_SHA256 = "400d0c377269792a7454d6421e803f5f8995987a58ce63e9b55b61f8f694bb88"
DMG_SHA256 = "edddd0d5869caaa12e29e6996a04f11590280580976a119dbd42c24fa62fe18e"
BOOT_KC_SHA256 = "c80161fa3065883753fc285339281361a8469cbb6fb27653c88e2a22eb4807a4"
GRAPHICS_SHA256 = "297694fbc3e5252318d3f6bc5afab6452253fae4a3fdb54aefc6ea7e7c9c4832"
GRAPHICS_INFO_SHA256 = "65a58f19e44834e464c65fb595e73fa10f1356f4d4d9c46a94295467f99757bc"
BUILD_ID = "25G83"
EXPECTED_CANDIDATE_SHA256 = "eb48a437e5d98325a610ac09988159940268af803435fdea699d34a5541f4307"


def remaining(deadline, maximum):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("Offline check time budget expired")
    return min(seconds, maximum)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def require_digest(path, expected, label):
    actual = digest(path)
    if actual != expected:
        raise ValueError(f"{label} digest mismatch: {actual}")
    return actual


def verify_sources(root):
    manifest_path = root / "source-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest["Files"].items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("Invalid source manifest path")
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Source manifest path leaves the source directory")
        require_digest(path, expected, f"Source {name}")
    if Path(__file__).name not in manifest["Files"]:
        raise ValueError("Link checker is not included in the source manifest")
    return manifest, digest(manifest_path)


def safe_extract(archive, destination, ignored_symlinks=()):
    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            relative = PurePosixPath(entry.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in entry.filename:
                raise ValueError("Unsafe archive path")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                if entry.filename in ignored_symlinks:
                    continue
                raise ValueError("Archive symlinks are not accepted")
        for entry in source.infolist():
            if entry.filename not in ignored_symlinks:
                source.extract(entry, destination)


def fetch_source(staging, repository, commit, expected):
    url = f"https://codeload.github.com/acidanthera/{repository}/zip/{commit}"
    archive = staging / f"{repository}.zip"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Pinned {repository} archive digest mismatch")
    archive.write_bytes(data)
    # AUDK's unused emulator include shortcut points outside the source tree.
    # The kernel-injection utility does not use EmulatorPkg; never create it.
    ignored = (f"audk-{commit}/EmulatorPkg/Unix/Host/X11IncludeHack",) if repository == "audk" else ()
    safe_extract(archive, staging, ignored)
    return staging / f"{repository}-{commit}"


def run_logged(args, cwd, log_path, timeout=300):
    try:
        result = subprocess.run([str(arg) for arg in args], cwd=cwd,
                                capture_output=True, text=True, errors="replace",
                                timeout=timeout)
    except subprocess.TimeoutExpired as error:
        def readable(value):
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
        log_path.write_text(readable(error.stdout) + "\n" + readable(error.stderr), encoding="utf-8")
        raise
    output = result.stdout + "\n" + result.stderr
    log_path.write_text(output, encoding="utf-8")
    return result, output


def unpack_candidate(root, staging, manifest, receipt):
    archive = root / "dist" / "NVGopFramebuffer2803-UNTESTED.zip"
    destination = staging / "candidate"
    safe_extract(archive, destination)
    report = json.loads((destination / "build-report.json").read_text(encoding="utf-8"))
    for name in ("NVGopFramebuffer.cpp", "module.cpp", "Info.plist"):
        if report["SourceManifest"]["Files"][name] != manifest["Files"][name]:
            raise ValueError(f"Candidate was built from different driver input: {name}")
    bundle = destination / "NVGopFramebuffer2803.kext"
    binary = bundle / "Contents" / "MacOS" / "NVGopFramebuffer"
    info = bundle / "Contents" / "Info.plist"
    binary_sha = require_digest(binary, report["BinarySHA256"], "Candidate binary")
    receipt["CandidateBinarySHA256"] = binary_sha
    receipt["ExpectedCandidateBinarySHA256"] = EXPECTED_CANDIDATE_SHA256
    receipt["CandidateMatchesPinnedBinary"] = binary_sha == EXPECTED_CANDIDATE_SHA256
    if not receipt["CandidateMatchesPinnedBinary"]:
        raise ValueError("New build differs from the locally audited candidate binary")
    require_digest(info, manifest["Files"]["Info.plist"], "Candidate Info.plist")
    if plistlib.loads(info.read_bytes())["CFBundleIdentifier"] != "org.local.experimental.NVGopFramebuffer2803":
        raise ValueError("Unexpected candidate bundle identity")
    # This import occurs only after Darwin and source-integrity checks.
    sys.dont_write_bytecode = True
    from verify_kext import check
    check(binary.read_bytes(), "NVGopFramebuffer")
    return binary, info, binary_sha


def actual_pair_ok(output, binary):
    # TestKextInject prints the supplied executable argument, not bundle ID.
    return any(f"[OK] {binary} injected - Success" in line
               for line in output.splitlines())


def write_report(dist, report, logs):
    dist.mkdir(exist_ok=True)
    output = dist / "OC-link-check.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("check-report.json", json.dumps(report, indent=2))
        for path in sorted(logs.glob("*.log")):
            archive.write(path, f"logs/{path.name}")
    print(f"Offline link report: {output}", flush=True)


def main():
    # No workspace writes, downloads, mounts, or builds on Windows.
    if platform.system() != "Darwin":
        raise SystemExit("Requires macOS; no linking check or system change was performed.")
    root = Path(__file__).resolve().parent
    manifest, manifest_sha = verify_sources(root)
    clang = subprocess.run(["xcrun", "--find", "clang"], check=True,
                           text=True, capture_output=True).stdout.strip()
    compiler = subprocess.run([clang, "--version"], check=True,
                              text=True, capture_output=True).stdout
    if "Apple clang" not in compiler:
        raise ValueError("Apple clang is required")
    sdk = Path(subprocess.run(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], check=True,
        text=True, capture_output=True).stdout.strip())
    if not sdk.is_absolute() or not (sdk / "usr/include/stdlib.h").is_file():
        raise ValueError("macOS SDK with standard C headers is required")
    if any(character in str(sdk) for character in "$#\r\n"):
        raise ValueError("Unsupported macOS SDK path for make")
    build_root = root / "build"
    build_root.mkdir(exist_ok=True)
    deadline = time.monotonic() + 480
    report = {
        "State": "OfflineLinkCheckPending",
        "SourceManifestSHA256": manifest_sha,
        "OpenCoreCommit": OC_COMMIT, "OpenCoreArchiveSHA256": OC_SHA256,
        "AUDKCommit": AUDK_COMMIT, "AUDKArchiveSHA256": AUDK_SHA256,
        "MacOSSDKPath": str(sdk),
        "RecoveryDMGSHA256": DMG_SHA256,
        "ExpectedRecoveryBuild": BUILD_ID,
        "KernelExecuted": False, "DriverInstalled": False,
        "USBModified": False, "GUIBootVerified": False,
        "SafeRuntimeBootVerified": False,
        "DetectedOriginalReferences": True,
        "RuntimeCrossCollectionReferenceHandlingUnverified": True,
        "PinnedImageLocalAudit": {
            "OriginalGraphicsReferencesDetected": True,
            "RecheckedByThisRun": False,
            "IONDRVSupportGOTMetaClassSlot": "0xD21018",
            "OriginalIOFramebufferMetaClassTarget": "0xD0E040",
            "IONDRVSupportGOTVtableSlot": "0xD21060",
            "OriginalIOFramebufferVtableTarget": "0xD04248",
        },
        "Caveats": [
            "The official utility also applies test patches and adds a synthetic plist-only fixture.",
            "Its out.bin is discarded and must never be deployed or published.",
            "A successful Boot KC link does not validate later BaseSystem KC duplicate handling or fixed references.",
            "A local audit of the pinned Recovery found IONDRVSupport constructors/callbacks referring to original pageable Graphics targets.",
            "This framebuffer candidate does not provide GPU acceleration or Metal.",
        ],
    }
    success = False
    with tempfile.TemporaryDirectory(prefix="oc-link-check-", dir=build_root) as private:
        staging = Path(private)
        logs = staging / "logs"
        logs.mkdir()
        detach_device = None
        try:
            oc = fetch_source(staging, "OpenCorePkg", OC_COMMIT, OC_SHA256)
            audk = fetch_source(staging, "audk", AUDK_COMMIT, AUDK_SHA256)
            candidate_binary, candidate_info, candidate_sha = unpack_candidate(root, staging, manifest, report)
            report["CandidateBinarySHA256"] = candidate_sha
            utility_dir = oc / "Utilities" / "TestKextInject"
            # Apple's absolute clang path needs an explicit SDK on this runner.
            # A final makefile appends flags to both shared-object recipes and
            # the linker without replacing the official makefile's defaults.
            sdk_makefile = staging / "apple-sdk.mk"
            sdk_flags = "-isysroot " + shlex.quote(str(sdk))
            sdk_makefile.write_text(
                "SHARED_CFLAGS += " + sdk_flags + "\nLDFLAGS += " + sdk_flags + "\n",
                encoding="utf-8")
            result, _ = run_logged(
                ["make", "-f", "Makefile", "-f", str(sdk_makefile), "-j2",
                 "CC=" + clang, "DEBUG=1", "UDK_PATH=" + str(audk)],
                utility_dir, logs / "utility-build.log", timeout=remaining(deadline, 240))
            if result.returncode:
                raise RuntimeError(f"Official TestKextInject build failed ({result.returncode})")
            utility = utility_dir / "KextInject"
            if not utility.is_file():
                raise RuntimeError("Official TestKextInject executable is missing")
            report["TestKextInjectSHA256"] = digest(utility)

            recovery = staging / "recovery"
            # macrecovery implements Apple's session/asset-token protocol and
            # signed chunklist verification. Capture its output only in memory:
            # it can contain ephemeral download URLs/tokens, so never log it.
            downloader = subprocess.run(
                [sys.executable, "-B", str(oc / "Utilities" / "macrecovery" / "macrecovery.py"),
                 "-b", "Mac-CFF7D910A743CAAF", "-m", "00000000000000000",
                 "-os", "latest", "-o", str(recovery), "download"],
                cwd=staging, capture_output=True, timeout=remaining(deadline, 360))
            report["OfficialRecoveryDownloadExitCode"] = downloader.returncode
            if downloader.returncode:
                raise RuntimeError("Official macrecovery download or signed-image verification failed")
            del downloader
            dmg = recovery / "BaseSystem.dmg"
            require_digest(dmg, DMG_SHA256, "Recovery DMG")

            attachment = subprocess.run(
                ["hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(dmg)],
                check=True, capture_output=True, timeout=remaining(deadline, 90))
            entities = plistlib.loads(attachment.stdout)["system-entities"]
            devices = [entity["dev-entry"] for entity in entities if entity.get("dev-entry")]
            if devices:
                detach_device = devices[0]
            mounts = [Path(entity["mount-point"]) for entity in entities if entity.get("mount-point")]
            mount = next((point for point in mounts
                          if (point / "System/Library/CoreServices/SystemVersion.plist").is_file()), None)
            if mount is None:
                raise RuntimeError("Recovery system mount point was not found")
            version = plistlib.loads((mount / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
            report["RecoveryVersion"] = version
            if version.get("ProductBuildVersion") != BUILD_ID:
                raise ValueError("Recovery build differs from the locally verified image")
            boot = mount / "System/Library/KernelCollections/BootKernelExtensions.kc"
            stock = mount / "System/Library/Extensions/IOGraphicsFamily.kext"
            stock_binary = stock / "IOGraphicsFamily"
            stock_info = stock / "Info.plist"
            report["BootKernelCollectionSHA256"] = require_digest(boot, BOOT_KC_SHA256, "Boot KC")
            report["IOGraphicsFamilySHA256"] = require_digest(stock_binary, GRAPHICS_SHA256, "IOGraphicsFamily")
            report["IOGraphicsInfoSHA256"] = require_digest(stock_info, GRAPHICS_INFO_SHA256, "IOGraphics Info.plist")
            stock_plist = plistlib.loads(stock_info.read_bytes())
            if stock_plist.get("CFBundleIdentifier") != "com.apple.iokit.IOGraphicsFamily":
                raise ValueError("Unexpected stock graphics bundle identity")
            report["IOGraphicsVersion"] = stock_plist.get("CFBundleVersion")

            negative = staging / "negative"
            negative.mkdir()
            result, output = run_logged([utility, boot, candidate_binary, candidate_info],
                                        negative, logs / "gop-alone.log",
                                        timeout=remaining(deadline, 90))
            negative_failed = any(f"[FAIL] {candidate_binary} injected -" in line
                                  for line in output.splitlines())
            report["GOPAloneExitCode"] = result.returncode
            report["GOPAloneExpectedLinkFailureConfirmed"] = bool(result.returncode and negative_failed)
            positive = staging / "positive"
            positive.mkdir()
            result, output = run_logged(
                [utility, boot, stock_binary, stock_info, candidate_binary, candidate_info],
                positive, logs / "graphics-then-gop.log", timeout=remaining(deadline, 90))
            stock_ok = actual_pair_ok(output, stock_binary)
            candidate_ok = actual_pair_ok(output, candidate_binary)
            complete_ok = "[OK] Prelink inject complete success" in output
            report.update({"GraphicsThenGOPExitCode": result.returncode,
                           "IOGraphicsInjectionPassed": stock_ok,
                           "GOPInjectionPassed": candidate_ok,
                           "InjectionCompletePassed": complete_ok})
            success = (result.returncode == 0 and stock_ok and candidate_ok and complete_ok
                       and report["GOPAloneExpectedLinkFailureConfirmed"])
            if not success:
                raise RuntimeError("Stock graphics plus GOP offline injection did not fully pass")
            report["State"] = "OfflineBootKCLinkPassedRuntimeUnverified"
        except Exception as error:
            report["State"] = "OfflineLinkCheckFailed"
            report["ErrorType"] = type(error).__name__
            # Download-process output is never attached to an exception or log.
            report["Error"] = str(error)
        finally:
            if detach_device is not None:
                try:
                    result, _ = run_logged(["hdiutil", "detach", detach_device], staging,
                                           logs / "recovery-detach.log", timeout=45)
                    report["ReadOnlyRecoveryDetached"] = result.returncode == 0
                    if result.returncode:
                        success = False
                        report["State"] = "OfflineLinkCheckFailed"
                        report["DetachError"] = "Read-only Recovery mount could not be detached"
                except Exception as error:
                    success = False
                    report["State"] = "OfflineLinkCheckFailed"
                    report["DetachError"] = type(error).__name__
            # Only JSON/logs are packaged. Apple files and utility out.bin remain
            # in this owned temporary directory and are removed on exit.
            write_report(root / "dist", report, logs)
    if not success:
        raise SystemExit("Offline link check failed; inspect the report archive.")
    print("Offline Boot KC linking passed. Runtime safety and GUI remain unverified.")


if __name__ == "__main__":
    main()
