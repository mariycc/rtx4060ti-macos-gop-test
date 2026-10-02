// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bdwithganesh
// Adapted from OpenNVDA NVFramebuffer at commit
// 2044adc11ceea642b2798b1943c292891562ae2b. See LICENSE and provenance.json.
// Local source candidate only: existing BGRX32 GOP scan-out, PCI 10DE:2803.
// No modesetting, acceleration, GPU firmware, MMIO register writes, NVRAM,
// networking, timers, private XNU symbols, or direct writes to video memory.

#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/pci/IOPCIDevice.h>

#if !defined(__x86_64__) || !defined(__LP64__)
#error This experimental candidate requires an x86_64 LP64 kernel build.
#endif
static_assert(sizeof(IOPhysicalAddress) == 8, "64-bit physical addresses required");
static_assert(sizeof(IOByteCount) == 8, "64-bit aperture sizes required");

namespace {
constexpr IODisplayModeID kGopMode = 1;
constexpr UInt64 kMaxUInt32 = 0xFFFFFFFFULL;
constexpr UInt64 kMaxUInt64 = ~static_cast<UInt64>(0);
}

class NVGopFramebuffer : public IOFramebuffer {
    OSDeclareDefaultStructors(NVGopFramebuffer)

private:
    IODeviceMemory *fAperture {nullptr};
    UInt32 fWidth {0};
    UInt32 fHeight {0};
    UInt32 fRowBytes {0};

public:
    bool start(IOService *provider) override;
    void free(void) override;
    IODeviceMemory *getApertureRange(IOPixelAperture aperture) override;
    const char *getPixelFormats(void) override;
    IOItemCount getDisplayModeCount(void) override;
    IOReturn getDisplayModes(IODisplayModeID *modes) override;
    IOReturn getInformationForDisplayMode(IODisplayModeID mode,
                                         IODisplayModeInformation *info) override;
    UInt64 getPixelFormatsForDisplayMode(IODisplayModeID mode, IOIndex depth) override;
    IOReturn getPixelInformation(IODisplayModeID mode, IOIndex depth,
                                IOPixelAperture aperture, IOPixelInformation *info) override;
    IOReturn getCurrentDisplayMode(IODisplayModeID *mode, IOIndex *depth) override;
    IOReturn enableController(void) override;
    bool isConsoleDevice(void) override;
    IOReturn setDisplayMode(IODisplayModeID mode, IOIndex depth) override;
    IOItemCount getConnectionCount(void) override;
    IOReturn getAttribute(IOSelect attribute, uintptr_t *value) override;
    IOReturn getAttributeForConnection(IOIndex connection, IOSelect attribute,
                                       uintptr_t *value) override;
    IOReturn setAttributeForConnection(IOIndex connection, IOSelect attribute,
                                       uintptr_t value) override;
};

OSDefineMetaClassAndStructors(NVGopFramebuffer, IOFramebuffer)

bool NVGopFramebuffer::start(IOService *provider) {
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci || pci->configRead16(kIOPCIConfigVendorID) != 0x10DE ||
        pci->configRead16(kIOPCIConfigDeviceID) != 0x2803) {
        IOLog("NVGopFramebuffer: refused provider outside PCI 10DE:2803\n");
        return false;
    }
    if ((pci->configRead16(kIOPCIConfigCommand) & 0x0002) == 0) {
        IOLog("NVGopFramebuffer: PCI memory decoding disabled\n");
        return false;
    }

    PE_Video console;
    bzero(&console, sizeof(console));
    IOPlatformExpert *platform = getPlatform();
    if (!platform || platform->getConsoleInfo(&console) != kIOReturnSuccess) {
        IOLog("NVGopFramebuffer: console information unavailable\n");
        return false;
    }
    if (console.v_rotate != 0 || console.v_offset != 0) {
        IOLog("NVGopFramebuffer: unsupported console rotation=%u offset=0x%llx\n",
              static_cast<unsigned>(console.v_rotate),
              static_cast<unsigned long long>(console.v_offset));
        return false;
    }

    // Validate before narrowing PE_Video's native-width fields. Division avoids
    // overflow in width * 4; depth/stride must describe a complete BGRX32 row.
    const UInt64 width = static_cast<UInt64>(console.v_width);
    const UInt64 height = static_cast<UInt64>(console.v_height);
    const UInt64 rowBytes = static_cast<UInt64>(console.v_rowBytes);
    if (console.v_depth != 32 || !width || !height || !rowBytes ||
        width > kMaxUInt32 || height > kMaxUInt32 || rowBytes > kMaxUInt32 ||
        (rowBytes & 3) != 0 || width > rowBytes / 4 ||
        height > kMaxUInt64 / rowBytes) {
        IOLog("NVGopFramebuffer: rejected geometry w=%llu h=%llu row=%llu depth=%lu\n",
              static_cast<unsigned long long>(width),
              static_cast<unsigned long long>(height),
              static_cast<unsigned long long>(rowBytes),
              static_cast<unsigned long>(console.v_depth));
        return false;
    }

    // Apple IOBootNDRV normalizes both low console-address flag bits this way.
    const IOPhysicalAddress base = static_cast<IOPhysicalAddress>(console.v_baseAddr) &
                                  ~static_cast<IOPhysicalAddress>(3);
    const IOByteCount visible = static_cast<IOByteCount>(height * rowBytes);
    IODeviceMemory *bar1 = pci->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress1);
    if (!base || !bar1) {
        IOLog("NVGopFramebuffer: console base or BAR1 unavailable\n");
        return false;
    }
    const IOPhysicalAddress barStart = bar1->getPhysicalAddress();
    const IOByteCount barLength = bar1->getLength();
    if (!barLength || barLength > kMaxUInt64 - barStart) {
        IOLog("NVGopFramebuffer: invalid BAR1 physical range\n");
        return false;
    }
    // Never add end addresses: first establish subtraction is safe, then check
    // the entire visible surface fits in the remaining BAR1 aperture.
    if (base < barStart) {
        IOLog("NVGopFramebuffer: console precedes BAR1\n");
        return false;
    }
    const IOByteCount offset = static_cast<IOByteCount>(base - barStart);
    if (offset >= barLength || visible > barLength - offset) {
        IOLog("NVGopFramebuffer: console outside BAR1 base=0x%llx bar=0x%llx len=0x%llx visible=0x%llx\n",
              static_cast<unsigned long long>(base),
              static_cast<unsigned long long>(barStart),
              static_cast<unsigned long long>(barLength),
              static_cast<unsigned long long>(visible));
        return false;
    }
    fAperture = IODeviceMemory::withSubRange(bar1, offset, visible);
    if (!fAperture) {
        IOLog("NVGopFramebuffer: aperture allocation failed\n");
        return false;
    }
    fWidth = static_cast<UInt32>(width);
    fHeight = static_cast<UInt32>(height);
    fRowBytes = static_cast<UInt32>(rowBytes);
    IOLog("NVGopFramebuffer: GOP %ux%u row=%u base=0x%llx BAR1+0x%llx bytes=0x%llx\n",
          fWidth, fHeight, fRowBytes, static_cast<unsigned long long>(base),
          static_cast<unsigned long long>(offset), static_cast<unsigned long long>(visible));
    if (!IOFramebuffer::start(provider)) {
        IOLog("NVGopFramebuffer: IOFramebuffer::start failed\n");
        OSSafeReleaseNULL(fAperture);
        return false;
    }
    IOLog("NVGopFramebuffer: IOFramebuffer::start returned success\n");
    return true;
}

void NVGopFramebuffer::free(void) {
    OSSafeReleaseNULL(fAperture);
    IOFramebuffer::free();
}

IODeviceMemory *NVGopFramebuffer::getApertureRange(IOPixelAperture aperture) {
    if (aperture != kIOFBSystemAperture || !fAperture) return nullptr;
    fAperture->retain();
    return fAperture;
}

const char *NVGopFramebuffer::getPixelFormats(void) { return IO32BitDirectPixels "\0\0"; }
IOItemCount NVGopFramebuffer::getDisplayModeCount(void) { return 1; }
IOReturn NVGopFramebuffer::getDisplayModes(IODisplayModeID *modes) {
    if (!modes) return kIOReturnBadArgument;
    modes[0] = kGopMode;
    return kIOReturnSuccess;
}
IOReturn NVGopFramebuffer::getInformationForDisplayMode(IODisplayModeID mode,
                                                        IODisplayModeInformation *info) {
    if (mode != kGopMode || !info) return kIOReturnBadArgument;
    bzero(info, sizeof(*info));
    info->nominalWidth = fWidth;
    info->nominalHeight = fHeight;
    info->refreshRate = 60 << 16; // Retained upstream nominal timing; no mode programming.
    info->maxDepthIndex = 0;
    info->flags = kDisplayModeValidFlag | kDisplayModeSafeFlag | kDisplayModeDefaultFlag;
    return kIOReturnSuccess;
}
UInt64 NVGopFramebuffer::getPixelFormatsForDisplayMode(IODisplayModeID, IOIndex) { return 0; }
IOReturn NVGopFramebuffer::getPixelInformation(IODisplayModeID mode, IOIndex depth,
                                               IOPixelAperture aperture, IOPixelInformation *info) {
    if (mode != kGopMode || depth != 0 || aperture != kIOFBSystemAperture || !info)
        return kIOReturnBadArgument;
    bzero(info, sizeof(*info));
    info->bytesPerRow = fRowBytes;
    info->bitsPerPixel = 32;
    info->pixelType = kIORGBDirectPixels;
    info->componentCount = 3;
    info->bitsPerComponent = 8;
    info->componentMasks[0] = 0x00FF0000;
    info->componentMasks[1] = 0x0000FF00;
    info->componentMasks[2] = 0x000000FF;
    info->activeWidth = fWidth;
    info->activeHeight = fHeight;
    const char *format = IO32BitDirectPixels;
    size_t i = 0;
    while (format[i] && i < sizeof(info->pixelFormat) - 1) {
        info->pixelFormat[i] = format[i];
        ++i;
    }
    info->pixelFormat[i] = '\0';
    return kIOReturnSuccess;
}
IOReturn NVGopFramebuffer::getCurrentDisplayMode(IODisplayModeID *mode, IOIndex *depth) {
    if (mode) *mode = kGopMode;
    if (depth) *depth = 0;
    return kIOReturnSuccess;
}
IOReturn NVGopFramebuffer::enableController(void) { return kIOReturnSuccess; }
bool NVGopFramebuffer::isConsoleDevice(void) { return true; }
IOReturn NVGopFramebuffer::setDisplayMode(IODisplayModeID mode, IOIndex depth) {
    return mode == kGopMode && depth == 0 ? kIOReturnSuccess : kIOReturnUnsupported;
}
IOItemCount NVGopFramebuffer::getConnectionCount(void) { return 1; }
IOReturn NVGopFramebuffer::getAttribute(IOSelect attribute, uintptr_t *value) {
    if (attribute == kIOHardwareCursorAttribute) {
        if (value) *value = 0;
        return kIOReturnSuccess;
    }
    return IOFramebuffer::getAttribute(attribute, value);
}
IOReturn NVGopFramebuffer::getAttributeForConnection(IOIndex connection, IOSelect attribute,
                                                    uintptr_t *value) {
    if (connection != 0) return kIOReturnBadArgument;
    switch (attribute) {
        case kConnectionEnable:
            if (value) *value = 1;
            return kIOReturnSuccess;
        case kConnectionFlags:
            if (value) *value = 0;
            return kIOReturnSuccess;
        case kConnectionSupportsAppleSense:
        case kConnectionSupportsLLDDCSense:
        case kConnectionSupportsHLDDCSense:
            return kIOReturnUnsupported;
        default:
            return IOFramebuffer::getAttributeForConnection(connection, attribute, value);
    }
}
IOReturn NVGopFramebuffer::setAttributeForConnection(IOIndex connection, IOSelect attribute,
                                                    uintptr_t value) {
    if (connection != 0) return kIOReturnBadArgument;
    return attribute == kConnectionPower ? kIOReturnSuccess :
           IOFramebuffer::setAttributeForConnection(connection, attribute, value);
}
