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
No binary is supplied by this source preparation step. The two C++ sources passed
LLVM 20.1.8 syntax and type checks on Windows against MacKernelSDK commit
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

Status: source reviewed, Apple build recipe prepared but not run. Binary
code generation/linking, Darwin 25 symbol resolution, actual superclass ABI,
Recovery compatibility and graphical boot remain unverified. This folder has
not been copied to the USB, no kernel code has been executed, and no code has
been uploaded to GitHub. See README-RU.md for the next steps in Russian.
