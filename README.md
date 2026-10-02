# NVGopFramebuffer2803 source candidate

Local review candidate derived from the MIT-licensed OpenNVDA GOP fallback at
commit `2044adc11ceea642b2798b1943c292891562ae2b`. Original files are retained
byte-for-byte under `upstream/`; source URLs and SHA-256 hashes are in
`provenance.json`. `LICENSE` preserves the original notice.

This source publishes the existing boot-console surface as a single-mode
IOFramebuffer for PCI `10DE:2803`. It does not initialize the GPU, change the
display mode, load NVIDIA firmware, provide acceleration or Metal, change PCI
registers, or write video memory directly. It removes the upstream NVRAM,
network, process inspection, private message-buffer imports, HUD and timer code.
Bounded IOLog messages report startup and rejection reasons.

The source requires an x86_64 LP64 kernel build with compatible MacKernelSDK
headers and IOGraphicsFamily/IOPCIFamily interfaces. The upstream repository's
root README references `tools/build_kext.sh` and `macos-lab/workspace.sh`, which
are absent at the pinned commit. No upstream build scripts were executed.
The two C++ sources passed LLVM 20.1.8 syntax and type checks on Windows against MacKernelSDK commit
`3f750085caa17ec3a7880f11c11bf4f48cd6a164`, using the modern
`x86_64-apple-macos11.0` target and kernel/kext compiler flags.

Startup accepts only a nonempty 32-bit console with unsigned-32-bit geometry,
four-byte-aligned stride and `rowBytes >= width * 4`. Physical addresses stay
64-bit; the two low console-address flags are cleared following Apple IOBootNDRV.
The complete surface must fit in the existing BAR1 descriptor, checked without
adding end addresses. No BAR is resized. The single pixel format is BGRX32,
matching the recorded firmware GOP format 1 on this machine. Nominal 60 Hz is
inherited from the upstream one-mode implementation, not measured or programmed.
The console must be unrotated with zero separate video-memory offset, and PCI
memory decoding must already be enabled; this source never enables it itself.
The personality uses the `IOFramebuffer` match category, matching Apple's NDRV
personality, to avoid attaching a second framebuffer in a separate category.

For the recorded 1920x1080 console with 2048 pixels per scanline, the expected
stride is 8192 and the surface size is `0x870000`. Its recorded physical base is
`0x4000000000`. Actual kernel BAR1 ownership still needs validation.

`build_mac.py` and the manual `.github/workflows/build-kext.yml` prepare an Apple
toolchain build on macOS. GitHub's standard macOS runner is free for public
repositories; the workflow deliberately skips private repositories. It downloads
only the pinned MacKernelSDK archive, verifies source and SDK hashes, compiles
the two local sources and links with Apple's `ld -kext`. No upstream build
scripts, kernel installation, boot commands, signing changes or release
publication are performed. Actions are pinned to verified release commits.

`verify_kext.py` checks architecture, MH_KEXT_BUNDLE format, basic tables,
relocations, expected kmod symbols and C++ initialization before packaging. The
parser was checked against the official local WhateverGreen kext and rejected
six malformed/header-modified inputs. It does not resolve kernel imports or
prove compatibility with the executing Darwin kernel.

Windows LLVM 20.1.8 `ld64.lld` does not implement kext linking. Windows Controlled
Folder Access also rejected the local clang object-file write (Defender event
1123); the blocked write was not retried through another path or program.
The Windows compiler was used only for read-only source checking afterward.

## Verified build, untested hardware

The public source repository is
https://github.com/mariycc/rtx4060ti-macos-gop-test. Its first manual build succeeded:
https://github.com/mariycc/rtx4060ti-macos-gop-test/actions/runs/36995414551
from commit `0020ad02cadb34aa5ad9a1acec1a894e2bee3dbd`.

Apple clang 17 and Apple's `ld -kext` produced a 40,024-byte x86_64
MH_KEXT_BUNDLE with 421 dynamic relocations. The downloaded GitHub artifact
matched the digest displayed on the run page, and an independent local pass
of the format checker matched `build-report.json`. Binary SHA-256:
`eb48a437e5d98325a610ac09988159940268af803435fdea699d34a5541f4307`.

All 366 imported symbol names were found as external definitions in the
actual Tahoe 25.6.0 Recovery kernel collections: 274 in the kernel, 90 in
IOGraphicsFamily and two in IOPCIFamily. This is an offline presence check;
the target kernel has not loaded or linked this extension yet.

An offline comparison also matched all 353 superclass vtable entries, with
21 expected subclass overrides and no unexplained differences. The actual
IOFramebuffer superclass size is 464 bytes; the candidate starts its fields
at byte 464 and has a total size of 488 bytes.

The graphics dependency is in BaseSystemKernelExtensions.kc, while this
machine's OpenCore log shows injection into BootKernelExtensions.kc. Symbol
presence across both collections does not prove that the OpenCore linker can
see those definitions. `check_opencore_link_mac.py` is prepared to check the
real OpenCore 1.0.8 linker against the exact Recovery image, first with the
candidate alone, then with the stock Apple IOGraphicsFamily before it. It keeps
only reports and logs; its patched `out.bin` must never be used for booting.
The original Apple files are not published in this source repository.

The artifact is named `NVGopFramebuffer2803-UNTESTED`; the repository contains
source, not a release driver. Build-time reports retain the original source
manifest and the preparation-stage provenance for that exact commit.

Runtime symbol resolution, cross-collection initialization, Recovery
compatibility and graphical boot remain unverified. Kernel code has not been executed on
the target PC. This experiment does not provide acceleration or Metal.
See README-RU.md for the current status in Russian.
