"""Build an uninstalled, read-only PCI diagnostic kext with Apple tools.

This is not an RTX display driver. --verify is read-only and also runs on Windows.
No signing, installation, firmware upload, kernel loading or USB operation exists here.
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

PRODUCT = "AD106DiagnosticProbe"
VERSION = "0.1.0"
BUNDLE_ID = "org.local.experimental.AD106DiagnosticProbe"
TARGET_PCI = "0x280310DE"
SDK_COMMIT = "3f750085caa17ec3a7880f11c11bf4f48cd6a164"
SDK_SHA256 = "f028466e8a18cae2e95724152f915a44afc6352a8a80ae3d85567c55b6c1d60d"
SDK_URL = f"https://codeload.github.com/acidanthera/MacKernelSDK/zip/{SDK_COMMIT}"
SOURCES = json.loads(r'''{
  "Probe.cpp": "// SPDX-License-Identifier: MIT\n// Copyright (c) 2026 bdwithganesh\n// Minimal derivative of the OpenNVDA NVFBProbe survey; see LICENSENOTICE.\n#include <IOKit/IOService.h>\n#include <IOKit/IOMemoryDescriptor.h>\n#include <IOKit/pci/IOPCIDevice.h>\n#include <libkern/c++/OSArray.h>\n#include <libkern/libkern.h>\n\nclass AD106DiagnosticProbe : public IOService {\n    OSDeclareDefaultStructors(AD106DiagnosticProbe)\npublic:\n    IOService *probe(IOService *provider, SInt32 *score) override;\n};\n\nOSDefineMetaClassAndStructors(AD106DiagnosticProbe, IOService)\n\nnamespace {\nconstexpr UInt16 kVendor = 0x10de;\nconstexpr UInt16 kDevice = 0x2803;\nconstexpr UInt16 kMemoryDecode = 0x0002;\n\nstruct RegisterRead {\n    const char *name;\n    IOByteCount offset;\n};\n\n// No PROM, interrupt, display-head, reset or command registers are read.\nconstexpr RegisterRead kRegisters[] = {\n    {\"BOOT0\", 0x00000000},\n    {\"BOOT42\", 0x00000a00},\n    {\"USABLE_FB_MIB\", 0x001183a4},\n    {\"VGA_WORKSPACE_RAW\", 0x00625f04},\n    {\"SEC2_UCODE3_FUSE_RAW\", 0x00824148},\n    {\"GSP_UCODE9_FUSE_RAW\", 0x008241e0},\n};\n\nbool readRegister(IOMemoryMap *map, IOByteCount offset, UInt32 *value) {\n    if (!map || !value || (offset & (sizeof(UInt32) - 1))) return false;\n    const IOByteCount length = map->getLength();\n    if (offset > length || length - offset < sizeof(UInt32)) return false;\n    const IOVirtualAddress base = map->getVirtualAddress();\n    const IOVirtualAddress maximum = ~static_cast<IOVirtualAddress>(0);\n    if (!base || base > maximum - offset ||\n        base + offset > maximum - (sizeof(UInt32) - 1) ||\n        ((base + offset) & (sizeof(UInt32) - 1))) return false;\n    const volatile UInt32 *address = reinterpret_cast<const volatile UInt32 *>(base + offset);\n    *value = *address;\n    return true;\n}\n}  // namespace\n\nIOService *AD106DiagnosticProbe::probe(IOService *provider, SInt32 *score) {\n    printf(\"AD106DiagnosticProbe: BEGIN version=0.1.0\\n\");\n    OSObject *memoryOwner = nullptr;\n    IOMemoryDescriptor *bar0 = nullptr;\n    IOMemoryMap *mapping = nullptr;\n\n    do {\n        if (!IOService::probe(provider, score)) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=super-probe-declined\\n\");\n            break;\n        }\n        IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);\n        if (!pci || pci->isInactive()) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=provider-unavailable\\n\");\n            break;\n        }\n        const UInt16 vendor = pci->configRead16(static_cast<UInt8>(kIOPCIConfigVendorID));\n        const UInt16 device = pci->configRead16(static_cast<UInt8>(kIOPCIConfigDeviceID));\n        if (vendor != kVendor || device != kDevice) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=pci-id vendor=%04x device=%04x\\n\",\n                   static_cast<unsigned int>(vendor), static_cast<unsigned int>(device));\n            break;\n        }\n        const UInt16 command = pci->configRead16(static_cast<UInt8>(kIOPCIConfigCommand));\n        printf(\"AD106DiagnosticProbe: PCI vendor=%04x device=%04x command=%04x\\n\",\n               static_cast<unsigned int>(vendor), static_cast<unsigned int>(device),\n               static_cast<unsigned int>(command));\n        if (command == 0xffff || !(command & kMemoryDecode)) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=memory-decode-unavailable\\n\");\n            break;\n        }\n        const UInt32 classRevision = pci->configRead32(static_cast<UInt8>(kIOPCIConfigRevisionID));\n        const UInt32 subsystem = pci->configRead32(static_cast<UInt8>(kIOPCIConfigSubSystemVendorID));\n        printf(\"AD106DiagnosticProbe: PCI class-revision=%08x subsystem=%08x\\n\",\n               static_cast<unsigned int>(classRevision), static_cast<unsigned int>(subsystem));\n\n        // Avoid IOPCIDevice memory accessors: they can change tunnel-L1 policy.\n        // copyProperty holds the array; also retain the selected descriptor.\n        // PCI ranges can be general/subrange descriptors, not IODeviceMemory instances.\n        memoryOwner = pci->copyProperty(\"IODeviceMemory\");\n        OSArray *memory = OSDynamicCast(OSArray, memoryOwner);\n        if (memory) {\n            for (unsigned int i = 0; i < memory->getCount(); ++i) {\n                IOMemoryDescriptor *candidate = OSDynamicCast(IOMemoryDescriptor, memory->getObject(i));\n                if (candidate && (candidate->getTag() & 0xff) == kIOPCIConfigBaseAddress0) {\n                    bar0 = candidate;\n                    bar0->retain();\n                    break;\n                }\n            }\n        }\n        if (!bar0) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=published-bar0-unavailable\\n\");\n            break;\n        }\n        const IOPhysicalAddress physical = bar0->getPhysicalAddress();\n        const IOByteCount length = bar0->getLength();\n        const IOPhysicalAddress maximum = ~static_cast<IOPhysicalAddress>(0);\n        printf(\"AD106DiagnosticProbe: BAR0 physical=%llx length=%llx\\n\",\n               static_cast<unsigned long long>(physical), static_cast<unsigned long long>(length));\n        if (!physical || !length || length > maximum - physical) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=published-bar0-invalid\\n\");\n            break;\n        }\n        mapping = bar0->map(kIOMapReadOnly | kIOMapInhibitCache | kIOMapUnique);\n        if (!mapping || !mapping->getVirtualAddress() || !mapping->getLength()) {\n            printf(\"AD106DiagnosticProbe: SKIP reason=readonly-map-unavailable\\n\");\n            break;\n        }\n        for (const auto &reg : kRegisters) {\n            UInt32 value = 0;\n            if (!readRegister(mapping, reg.offset, &value)) {\n                printf(\"AD106DiagnosticProbe: SKIP reason=register-range name=%s offset=%08x\\n\",\n                       reg.name, static_cast<unsigned int>(reg.offset));\n                continue;\n            }\n            printf(\"AD106DiagnosticProbe: READ name=%s offset=%08x raw=%08x\\n\",\n                   reg.name, static_cast<unsigned int>(reg.offset), static_cast<unsigned int>(value));\n        }\n    } while (false);\n\n    if (mapping) mapping->release();\n    if (bar0) bar0->release();\n    if (memoryOwner) memoryOwner->release();\n    printf(\"AD106DiagnosticProbe: END decline-attachment\\n\");\n    return nullptr;\n}\n",
  "module.cpp": "// SPDX-License-Identifier: MIT\n// Copyright (c) 2026 bdwithganesh\n// OpenNVDA-derived kmod metadata; see LICENSENOTICE.\n#include <mach/mach_types.h>\n#include <mach/kmod.h>\n#include <libkern/libkern.h>\n\nextern \"C\" {\nextern kern_return_t _start(kmod_info_t *, void *);\nextern kern_return_t _stop(kmod_info_t *, void *);\n\nstatic kern_return_t diagnosticModuleStart(kmod_info_t *, void *) {\n    printf(\"AD106DiagnosticProbe: MODULE_START version=0.1.0\\n\");\n    return KERN_SUCCESS;\n}\n\nstatic kern_return_t diagnosticModuleStop(kmod_info_t *, void *) {\n    printf(\"AD106DiagnosticProbe: MODULE_STOP\\n\");\n    return KERN_SUCCESS;\n}\n\nKMOD_EXPLICIT_DECL(org.local.experimental.AD106DiagnosticProbe, \"0.1.0\", _start, _stop)\n__attribute__((visibility(\"hidden\"))) kmod_start_func_t *_realmain = diagnosticModuleStart;\n__attribute__((visibility(\"hidden\"))) kmod_stop_func_t *_antimain = diagnosticModuleStop;\n__attribute__((visibility(\"hidden\"))) int _kext_apple_cc = __APPLE_CC__;\n}\n",
  "Info.plist": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>CFBundleDevelopmentRegion</key><string>English</string>\n    <key>CFBundleExecutable</key><string>AD106DiagnosticProbe</string>\n    <key>CFBundleIdentifier</key><string>org.local.experimental.AD106DiagnosticProbe</string>\n    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n    <key>CFBundleName</key><string>AD106DiagnosticProbe</string>\n    <key>CFBundlePackageType</key><string>KEXT</string>\n    <key>CFBundleShortVersionString</key><string>0.1.0</string>\n    <key>CFBundleVersion</key><string>0.1.0</string>\n    <key>OSBundleRequired</key><string>Root</string>\n    <key>IOKitPersonalities</key>\n    <dict>\n        <key>AD106DiagnosticProbe</key>\n        <dict>\n            <key>CFBundleIdentifier</key><string>org.local.experimental.AD106DiagnosticProbe</string>\n            <key>IOClass</key><string>AD106DiagnosticProbe</string>\n            <key>IOProviderClass</key><string>IOPCIDevice</string>\n            <key>IOMatchCategory</key><string>AD106DiagnosticProbe</string>\n            <key>IOPCIMatch</key><string>0x280310DE</string>\n            <key>IOProbeScore</key><integer>0</integer>\n        </dict>\n    </dict>\n    <key>OSBundleLibraries</key>\n    <dict>\n        <key>com.apple.kpi.iokit</key><string>8.0.0</string>\n        <key>com.apple.kpi.libkern</key><string>8.0.0</string>\n        <key>com.apple.kpi.mach</key><string>8.0.0</string>\n        <key>com.apple.iokit.IOPCIFamily</key><string>2.9</string>\n    </dict>\n</dict>\n</plist>\n",
  "LICENSENOTICE": "AD106DiagnosticProbe is a minimal derivative of the OpenNVDA NVFBProbe\nregister survey and kmod metadata. Its diagnostic register offsets and\nbasic probe/read structure originate from:\nhttps://github.com/bdwithganesh/OpenNVDA\nPinned upstream revision: da0c53d0a2a0b69b658c9e26b4cfa51946fff5f5\nUpstream paths: drivers/NVFBProbe/NVFBProbe.cpp and kext module.cpp wiring.\n\nThis local derivative removes firmware staging/execution, PCI writes,\ninterrupts, power/reset operations, VBIOS reads and display takeover.\nThe upstream MIT notice follows.\n\nMIT License\n\nCopyright (c) 2026 bdwithganesh\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n"
}''')
SDK_LICENSE = r'''APPLE PUBLIC SOURCE LICENSE
Version 2.0 - August 6, 2003

Please read this License carefully before downloading this software.
By downloading or using this software, you are agreeing to be bound by
the terms of this License. If you do not or cannot agree to the terms
of this License, please do not download or use the software.

1. General; Definitions. This License applies to any program or other
work which Apple Computer, Inc. ("Apple") makes publicly available and
which contains a notice placed by Apple identifying such program or
work as "Original Code" and stating that it is subject to the terms of
this Apple Public Source License version 2.0 ("License"). As used in
this License:

1.1 "Applicable Patent Rights" mean: (a) in the case where Apple is
the grantor of rights, (i) claims of patents that are now or hereafter
acquired, owned by or assigned to Apple and (ii) that cover subject
matter contained in the Original Code, but only to the extent
necessary to use, reproduce and/or distribute the Original Code
without infringement; and (b) in the case where You are the grantor of
rights, (i) claims of patents that are now or hereafter acquired,
owned by or assigned to You and (ii) that cover subject matter in Your
Modifications, taken alone or in combination with Original Code.

1.2 "Contributor" means any person or entity that creates or
contributes to the creation of Modifications.

1.3 "Covered Code" means the Original Code, Modifications, the
combination of Original Code and any Modifications, and/or any
respective portions thereof.

1.4 "Externally Deploy" means: (a) to sublicense, distribute or
otherwise make Covered Code available, directly or indirectly, to
anyone other than You; and/or (b) to use Covered Code, alone or as
part of a Larger Work, in any way to provide a service, including but
not limited to delivery of content, through electronic communication
with a client other than You.

1.5 "Larger Work" means a work which combines Covered Code or portions
thereof with code not governed by the terms of this License.

1.6 "Modifications" mean any addition to, deletion from, and/or change
to, the substance and/or structure of the Original Code, any previous
Modifications, the combination of Original Code and any previous
Modifications, and/or any respective portions thereof. When code is
released as a series of files, a Modification is: (a) any addition to
or deletion from the contents of a file containing Covered Code;
and/or (b) any new file or other representation of computer program
statements that contains any part of Covered Code.

1.7 "Original Code" means (a) the Source Code of a program or other
work as originally made available by Apple under this License,
including the Source Code of any updates or upgrades to such programs
or works made available by Apple under this License, and that has been
expressly identified by Apple as such in the header file(s) of such
work; and (b) the object code compiled from such Source Code and
originally made available by Apple under this License.

1.8 "Source Code" means the human readable form of a program or other
work that is suitable for making modifications to it, including all
modules it contains, plus any associated interface definition files,
scripts used to control compilation and installation of an executable
(object code).

1.9 "You" or "Your" means an individual or a legal entity exercising
rights under this License. For legal entities, "You" or "Your"
includes any entity which controls, is controlled by, or is under
common control with, You, where "control" means (a) the power, direct
or indirect, to cause the direction or management of such entity,
whether by contract or otherwise, or (b) ownership of fifty percent
(50%) or more of the outstanding shares or beneficial ownership of
such entity.

2. Permitted Uses; Conditions & Restrictions. Subject to the terms
and conditions of this License, Apple hereby grants You, effective on
the date You accept this License and download the Original Code, a
world-wide, royalty-free, non-exclusive license, to the extent of
Apple's Applicable Patent Rights and copyrights covering the Original
Code, to do the following:

2.1 Unmodified Code. You may use, reproduce, display, perform,
internally distribute within Your organization, and Externally Deploy
verbatim, unmodified copies of the Original Code, for commercial or
non-commercial purposes, provided that in each instance:

(a) You must retain and reproduce in all copies of Original Code the
copyright and other proprietary notices and disclaimers of Apple as
they appear in the Original Code, and keep intact all notices in the
Original Code that refer to this License; and

(b) You must include a copy of this License with every copy of Source
Code of Covered Code and documentation You distribute or Externally
Deploy, and You may not offer or impose any terms on such Source Code
that alter or restrict this License or the recipients' rights
hereunder, except as permitted under Section 6.

2.2 Modified Code. You may modify Covered Code and use, reproduce,
display, perform, internally distribute within Your organization, and
Externally Deploy Your Modifications and Covered Code, for commercial
or non-commercial purposes, provided that in each instance You also
meet all of these conditions:

(a) You must satisfy all the conditions of Section 2.1 with respect to
the Source Code of the Covered Code;

(b) You must duplicate, to the extent it does not already exist, the
notice in Exhibit A in each file of the Source Code of all Your
Modifications, and cause the modified files to carry prominent notices
stating that You changed the files and the date of any change; and

(c) If You Externally Deploy Your Modifications, You must make
Source Code of all Your Externally Deployed Modifications either
available to those to whom You have Externally Deployed Your
Modifications, or publicly available. Source Code of Your Externally
Deployed Modifications must be released under the terms set forth in
this License, including the license grants set forth in Section 3
below, for as long as you Externally Deploy the Covered Code or twelve
(12) months from the date of initial External Deployment, whichever is
longer. You should preferably distribute the Source Code of Your
Externally Deployed Modifications electronically (e.g. download from a
web site).

2.3 Distribution of Executable Versions. In addition, if You
Externally Deploy Covered Code (Original Code and/or Modifications) in
object code, executable form only, You must include a prominent
notice, in the code itself as well as in related documentation,
stating that Source Code of the Covered Code is available under the
terms of this License with information on how and where to obtain such
Source Code.

2.4 Third Party Rights. You expressly acknowledge and agree that
although Apple and each Contributor grants the licenses to their
respective portions of the Covered Code set forth herein, no
assurances are provided by Apple or any Contributor that the Covered
Code does not infringe the patent or other intellectual property
rights of any other entity. Apple and each Contributor disclaim any
liability to You for claims brought by any other entity based on
infringement of intellectual property rights or otherwise. As a
condition to exercising the rights and licenses granted hereunder, You
hereby assume sole responsibility to secure any other intellectual
property rights needed, if any. For example, if a third party patent
license is required to allow You to distribute the Covered Code, it is
Your responsibility to acquire that license before distributing the
Covered Code.

3. Your Grants. In consideration of, and as a condition to, the
licenses granted to You under this License, You hereby grant to any
person or entity receiving or distributing Covered Code under this
License a non-exclusive, royalty-free, perpetual, irrevocable license,
under Your Applicable Patent Rights and other intellectual property
rights (other than patent) owned or controlled by You, to use,
reproduce, display, perform, modify, sublicense, distribute and
Externally Deploy Your Modifications of the same scope and extent as
Apple's licenses under Sections 2.1 and 2.2 above.

4. Larger Works. You may create a Larger Work by combining Covered
Code with other code not governed by the terms of this License and
distribute the Larger Work as a single product. In each such instance,
You must make sure the requirements of this License are fulfilled for
the Covered Code or any portion thereof.

5. Limitations on Patent License. Except as expressly stated in
Section 2, no other patent rights, express or implied, are granted by
Apple herein. Modifications and/or Larger Works may require additional
patent licenses from Apple which Apple may grant in its sole
discretion.

6. Additional Terms. You may choose to offer, and to charge a fee for,
warranty, support, indemnity or liability obligations and/or other
rights consistent with the scope of the license granted herein
("Additional Terms") to one or more recipients of Covered Code.
However, You may do so only on Your own behalf and as Your sole
responsibility, and not on behalf of Apple or any Contributor. You
must obtain the recipient's agreement that any such Additional Terms
are offered by You alone, and You hereby agree to indemnify, defend
and hold Apple and every Contributor harmless for any liability
incurred by or claims asserted against Apple or such Contributor by
reason of any such Additional Terms.

7. Versions of the License. Apple may publish revised and/or new
versions of this License from time to time. Each version will be given
a distinguishing version number. Once Original Code has been published
under a particular version of this License, You may continue to use it
under the terms of that version. You may also choose to use such
Original Code under the terms of any subsequent version of this
License published by Apple. No one other than Apple has the right to
modify the terms applicable to Covered Code created under this
License.

8. NO WARRANTY OR SUPPORT. The Covered Code may contain in whole or in
part pre-release, untested, or not fully tested works. The Covered
Code may contain errors that could cause failures or loss of data, and
may be incomplete or contain inaccuracies. You expressly acknowledge
and agree that use of the Covered Code, or any portion thereof, is at
Your sole and entire risk. THE COVERED CODE IS PROVIDED "AS IS" AND
WITHOUT WARRANTY, UPGRADES OR SUPPORT OF ANY KIND AND APPLE AND
APPLE'S LICENSOR(S) (COLLECTIVELY REFERRED TO AS "APPLE" FOR THE
PURPOSES OF SECTIONS 8 AND 9) AND ALL CONTRIBUTORS EXPRESSLY DISCLAIM
ALL WARRANTIES AND/OR CONDITIONS, EXPRESS OR IMPLIED, INCLUDING, BUT
NOT LIMITED TO, THE IMPLIED WARRANTIES AND/OR CONDITIONS OF
MERCHANTABILITY, OF SATISFACTORY QUALITY, OF FITNESS FOR A PARTICULAR
PURPOSE, OF ACCURACY, OF QUIET ENJOYMENT, AND NONINFRINGEMENT OF THIRD
PARTY RIGHTS. APPLE AND EACH CONTRIBUTOR DOES NOT WARRANT AGAINST
INTERFERENCE WITH YOUR ENJOYMENT OF THE COVERED CODE, THAT THE
FUNCTIONS CONTAINED IN THE COVERED CODE WILL MEET YOUR REQUIREMENTS,
THAT THE OPERATION OF THE COVERED CODE WILL BE UNINTERRUPTED OR
ERROR-FREE, OR THAT DEFECTS IN THE COVERED CODE WILL BE CORRECTED. NO
ORAL OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE, AN APPLE
AUTHORIZED REPRESENTATIVE OR ANY CONTRIBUTOR SHALL CREATE A WARRANTY.
You acknowledge that the Covered Code is not intended for use in the
operation of nuclear facilities, aircraft navigation, communication
systems, or air traffic control machines in which case the failure of
the Covered Code could lead to death, personal injury, or severe
physical or environmental damage.

9. LIMITATION OF LIABILITY. TO THE EXTENT NOT PROHIBITED BY LAW, IN NO
EVENT SHALL APPLE OR ANY CONTRIBUTOR BE LIABLE FOR ANY INCIDENTAL,
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR RELATING
TO THIS LICENSE OR YOUR USE OR INABILITY TO USE THE COVERED CODE, OR
ANY PORTION THEREOF, WHETHER UNDER A THEORY OF CONTRACT, WARRANTY,
TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY OR OTHERWISE, EVEN IF
APPLE OR SUCH CONTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES AND NOTWITHSTANDING THE FAILURE OF ESSENTIAL PURPOSE OF ANY
REMEDY. SOME JURISDICTIONS DO NOT ALLOW THE LIMITATION OF LIABILITY OF
INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY
TO YOU. In no event shall Apple's total liability to You for all
damages (other than as may be required by applicable law) under this
License exceed the amount of fifty dollars ($50.00).

10. Trademarks. This License does not grant any rights to use the
trademarks or trade names "Apple", "Apple Computer", "Mac", "Mac OS",
"QuickTime", "QuickTime Streaming Server" or any other trademarks,
service marks, logos or trade names belonging to Apple (collectively
"Apple Marks") or to any trademark, service mark, logo or trade name
belonging to any Contributor. You agree not to use any Apple Marks in
or as part of the name of products derived from the Original Code or
to endorse or promote products derived from the Original Code other
than as expressly permitted by and in strict compliance at all times
with Apple's third party trademark usage guidelines which are posted
at http://www.apple.com/legal/guidelinesfor3rdparties.html.

11. Ownership. Subject to the licenses granted under this License,
each Contributor retains all rights, title and interest in and to any
Modifications made by such Contributor. Apple retains all rights,
title and interest in and to the Original Code and any Modifications
made by or on behalf of Apple ("Apple Modifications"), and such Apple
Modifications will not be automatically subject to this License. Apple
may, at its sole discretion, choose to license such Apple
Modifications under this License, or on different terms from those
contained in this License or may choose not to license them at all.

12. Termination.

12.1 Termination. This License and the rights granted hereunder will
terminate:

(a) automatically without notice from Apple if You fail to comply with
any term(s) of this License and fail to cure such breach within 30
days of becoming aware of such breach;

(b) immediately in the event of the circumstances described in Section
13.5(b); or

(c) automatically without notice from Apple if You, at any time during
the term of this License, commence an action for patent infringement
against Apple; provided that Apple did not first commence
an action for patent infringement against You in that instance.

12.2 Effect of Termination. Upon termination, You agree to immediately
stop any further use, reproduction, modification, sublicensing and
distribution of the Covered Code. All sublicenses to the Covered Code
which have been properly granted prior to termination shall survive
any termination of this License. Provisions which, by their nature,
should remain in effect beyond the termination of this License shall
survive, including but not limited to Sections 3, 5, 8, 9, 10, 11,
12.2 and 13. No party will be liable to any other for compensation,
indemnity or damages of any sort solely as a result of terminating
this License in accordance with its terms, and termination of this
License will be without prejudice to any other right or remedy of
any party.

13. Miscellaneous.

13.1 Government End Users. The Covered Code is a "commercial item" as
defined in FAR 2.101. Government software and technical data rights in
the Covered Code include only those rights customarily provided to the
public as defined in this License. This customary commercial license
in technical data and software is provided in accordance with FAR
12.211 (Technical Data) and 12.212 (Computer Software) and, for
Department of Defense purchases, DFAR 252.227-7015 (Technical Data --
Commercial Items) and 227.7202-3 (Rights in Commercial Computer
Software or Computer Software Documentation). Accordingly, all U.S.
Government End Users acquire Covered Code with only those rights set
forth herein.

13.2 Relationship of Parties. This License will not be construed as
creating an agency, partnership, joint venture or any other form of
legal association between or among You, Apple or any Contributor, and
You will not represent to the contrary, whether expressly, by
implication, appearance or otherwise.

13.3 Independent Development. Nothing in this License will impair
Apple's right to acquire, license, develop, have others develop for
it, market and/or distribute technology or products that perform the
same or similar functions as, or otherwise compete with,
Modifications, Larger Works, technology or products that You may
develop, produce, market or distribute.

13.4 Waiver; Construction. Failure by Apple or any Contributor to
enforce any provision of this License will not be deemed a waiver of
future enforcement of that or any other provision. Any law or
regulation which provides that the language of a contract shall be
construed against the drafter will not apply to this License.

13.5 Severability. (a) If for any reason a court of competent
jurisdiction finds any provision of this License, or portion thereof,
to be unenforceable, that provision of the License will be enforced to
the maximum extent permissible so as to effect the economic benefits
and intent of the parties, and the remainder of this License will
continue in full force and effect. (b) Notwithstanding the foregoing,
if applicable law prohibits or restricts You from fully and/or
specifically complying with Sections 2 and/or 3 or prevents the
enforceability of either of those Sections, this License will
immediately terminate and You must immediately discontinue any use of
the Covered Code and destroy all copies of it that are in your
possession or control.

13.6 Dispute Resolution. Any litigation or other dispute resolution
between You and Apple relating to this License shall take place in the
Northern District of California, and You and Apple hereby consent to
the personal jurisdiction of, and venue in, the state and federal
courts within that District with respect to this License. The
application of the United Nations Convention on Contracts for the
International Sale of Goods is expressly excluded.

13.7 Entire Agreement; Governing Law. This License constitutes the
entire agreement between the parties with respect to the subject
matter hereof. This License shall be governed by the laws of the
United States and the State of California, except that body of
California law concerning conflicts of law.

Where You are located in the province of Quebec, Canada, the following
clause applies: The parties hereby confirm that they have requested
that this License and all related documents be drafted in English. Les
parties ont exige que le present contrat et tous les documents
connexes soient rediges en anglais.

EXHIBIT A.

"Portions Copyright (c) 1999-2003 Apple Computer, Inc. All Rights
Reserved.

This file contains Original Code and/or Modifications of Original Code
as defined in and that are subject to the Apple Public Source License
Version 2.0 (the 'License'). You may not use this file except in
compliance with the License. Please obtain a copy of the License at
http://www.opensource.apple.com/apsl/ and read it before using this
file.

The Original Code and all software distributed under the License are
distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
Please see the License for the specific language governing rights and
limitations under the License."
'''
SDK_LICENSE_SHA256 = "e5881019d8766c1e88a5fe1dbca4ba40c78011d41fcb18f6e9f50df60182685b"
ALLOWED_DEPENDENCIES = {
    "com.apple.kpi.iokit", "com.apple.kpi.libkern", "com.apple.kpi.mach",
    "com.apple.iokit.IOPCIFamily"
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    return subprocess.run([str(a) for a in args], check=True, text=True,
                          capture_output=True).stdout.strip()


def source_report():
    required = {"Probe.cpp", "module.cpp", "Info.plist", "LICENSENOTICE"}
    if not required <= set(SOURCES):
        raise ValueError("Required reviewed sources are absent")
    if sha256(SDK_LICENSE.encode("utf-8")) != SDK_LICENSE_SHA256:
        raise ValueError("Embedded MacKernelSDK license mismatch")
    info = plistlib.loads(SOURCES["Info.plist"].encode("utf-8"))
    if (info.get("CFBundleIdentifier") != BUNDLE_ID or
            info.get("CFBundleExecutable") != PRODUCT or
            info.get("CFBundleVersion") != VERSION or
            info.get("OSBundleRequired") != "Root"):
        raise ValueError("Unexpected diagnostic bundle metadata")
    libraries = info.get("OSBundleLibraries", {})
    if set(libraries) != ALLOWED_DEPENDENCIES:
        raise ValueError("Unexpected diagnostic dependencies")
    personalities = info.get("IOKitPersonalities", {})
    if len(personalities) != 1:
        raise ValueError("Expected exactly one diagnostic personality")
    personality = next(iter(personalities.values()))
    if (personality.get("IOClass") != PRODUCT or
            personality.get("CFBundleIdentifier") != BUNDLE_ID or
            personality.get("IOProviderClass") != "IOPCIDevice" or
            personality.get("IOPCIMatch", "").upper() != TARGET_PCI.upper()):
        raise ValueError("Unexpected class, provider or PCI match")
    return {"Product": PRODUCT, "Version": VERSION, "BundleIdentifier": BUNDLE_ID,
            "TargetPCI": "10DE:2803", "EmbeddedSourceSHA256": {
                name: sha256(content.encode("utf-8")) for name, content in sorted(SOURCES.items())},
            "MacKernelSDKCommit": SDK_COMMIT, "MacKernelSDKArchiveSHA256": SDK_SHA256,
            "MacKernelSDKLicenseSHA256": SDK_LICENSE_SHA256,
            "Dependencies": libraries, "GraphicsDriver": False,
            "GPUAcceleration": False, "RuntimeTested": False}


def check_format(data):
    """Thin x86_64 MH_KEXT_BUNDLE bounds, symbol and relocation validation."""
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
            for i in range(segment[9]):
                sec = struct.unpack_from("<16s16sQQIIIIIIII", data, offset + 72 + i * 80)
                name = sec[0].split(b"\0", 1)[0].decode("ascii")
                sec_type = sec[8] & 0xFF
                require(sec_type not in (7, 8), "Lazy pointers or symbol stubs found")
                if sec_type not in (1, 12, 18):
                    require(sec[4] <= len(data) and sec[3] <= len(data) - sec[4],
                            "Section outside file")
                require(sec[6] <= len(data) and sec[7] <= (len(data) - sec[6]) // 8,
                        "Section relocation table outside file")
                sections.append({"Name": name, "Segment": sec[1].split(b"\0", 1)[0].decode("ascii"),
                                 "Bytes": sec[3], "Relocations": sec[7]})
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
    strings, defined, exports, imports = data[str_offset:str_offset + str_size], set(), set(), set()
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
            if typ & 1:
                exports.add(name)
    require({"_kmod_info", "__start", "__stop", "__realmain", "__antimain"} <= defined,
            "Missing kmod entry points or callback wiring")
    require(any(n.startswith("__ZTV") and PRODUCT in n for n in defined), "Missing diagnostic IOService vtable")
    require(any(s["Name"] == "__mod_init_func" and s["Bytes"] >= 8 for s in sections),
            "Missing C++ module initialization")
    require(not imports or dynamic_relocations or any(s["Relocations"] for s in sections),
            "Imports without relocation tables")
    require(BUNDLE_ID.encode() in data, "Missing kmod bundle identity")
    require(b"AD106DiagnosticProbe: MODULE_START version=0.1.0" in data and
            b"AD106DiagnosticProbe: BEGIN" in data and
            b"AD106DiagnosticProbe: END decline-attachment" in data,
            "Missing required diagnostic markers")
    forbidden_import_tokens = ("IOFramebuffer", "IOGraphics", "IOAccel", "Lilu",
                               "configWrite", "setMemoryEnable", "setBusMasterEnable")
    require(not any(t in n for t in forbidden_import_tokens for n in imports),
            "Unexpected graphics, Lilu or PCI write import")
    return {"Architecture": "x86_64", "MachOType": "MH_KEXT_BUNDLE", "CPUSubtype": subtype,
            "HeaderFlags": hex(flags), "Sections": sections, "DynamicRelocations": dynamic_relocations,
            "SectionRelocations": sum(s["Relocations"] for s in sections),
            "Imports": sorted(imports), "DefinedSymbols": sorted(defined), "Exports": sorted(exports),
            "FormatChecksPassed": True, "RuntimeTested": False, "GraphicsBootVerified": False}


def boot_exports(nm, boot_kc):
    output = command([nm, "--defined-only", "--extern-only", boot_kc])
    return set(re.findall(r"^\s*[0-9a-fA-F]+\s+[A-Za-z]\s+(\S+)\s*$", output, re.M))


def verify(bundle, boot_kc=None, nm=None):
    source = source_report()
    if not bundle.is_dir():
        raise ValueError("--verify requires an extracted AD106DiagnosticProbe.kext directory")
    info_data = (bundle / "Contents" / "Info.plist").read_bytes()
    if info_data != SOURCES["Info.plist"].encode("utf-8"):
        raise ValueError("Built Info.plist differs from reviewed source")
    binary = bundle / "Contents" / "MacOS" / PRODUCT
    data = binary.read_bytes()
    report = {"State": "FormatCheckedRuntimeUntested", "BinarySHA256": sha256(data),
              "BinaryBytes": len(data), "InfoSHA256": sha256(info_data),
              "Source": source, "Binary": check_format(data), "ImportsPresentInBootKC": False,
              "RuntimeTested": False, "GraphicsBootVerified": False,
              "DriverLoaded": False, "HardwareDiagnosticsCollected": False}
    if (boot_kc is None) != (nm is None):
        raise ValueError("Offline symbol audit needs --boot-kc and --nm together")
    if boot_kc is not None:
        available = boot_exports(nm, boot_kc)
        imports = set(report["Binary"]["Imports"])
        missing = imports - available
        report.update({"State": "OfflineBootKCImportPresenceCheckedRuntimeUntested",
                       "BootKCSHA256": sha256(boot_kc.read_bytes()),
                       "ImportedSymbols": len(imports), "ImportsPresentInBootKC": not missing,
                       "MissingImports": sorted(missing),
                       "Method": "Defined external nlist symbols across actual BootKC fileset; presence only"})
        if missing:
            raise ValueError("Offline symbol presence audit failed: " + json.dumps(report, indent=2))
    return report


def download_sdk(staging):
    with urllib.request.urlopen(SDK_URL, timeout=60) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024 or sha256(data) != SDK_SHA256:
        raise ValueError("MacKernelSDK digest or size mismatch")
    archive = staging / "MacKernelSDK.zip"
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > 5000 or sum(e.file_size for e in entries) > 96 * 1024 * 1024:
            raise ValueError("Oversized SDK archive")
        for entry in entries:
            relative = PurePosixPath(entry.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in entry.filename:
                raise ValueError("Unsafe SDK archive path")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("SDK archive symlinks are rejected")
        source.extractall(staging)
    sdk = staging / ("MacKernelSDK-" + SDK_COMMIT)
    if sha256((sdk / "LICENSE.txt").read_bytes()) != SDK_LICENSE_SHA256:
        raise ValueError("Downloaded SDK license differs from embedded notice")
    return sdk


def build():
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise SystemExit("Requires Intel macOS and Apple's compiler/linker; no kext was built.")
    source = source_report()
    root = Path(__file__).resolve().parent
    clang = command(["xcrun", "--find", "clang"])
    compiler_version = command([clang, "--version"])
    if "Apple clang" not in compiler_version:
        raise ValueError("Apple clang is required")
    linker = command(["xcrun", "--find", "ld"])
    resource = Path(command([clang, "-print-resource-dir"]))
    sdk_version = command(["xcrun", "--sdk", "macosx", "--show-sdk-version"])
    (root / "build").mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="ad106-apple-build-", dir=root / "build"))
    source_dir = staging / "source"
    source_dir.mkdir()
    for name, content in SOURCES.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
            raise ValueError("Invalid embedded source path")
        (source_dir / name).write_bytes(content.encode("utf-8"))
    sdk = download_sdk(staging)
    flags = ["-target", "x86_64-apple-macos11.0", "-x", "c++", "-std=c++14",
             "-mkernel", "-fapple-kext", "-DKERNEL", "-DKERNEL_PRIVATE", "-O2",
             "-fno-rtti", "-fno-exceptions", "-fno-builtin", "-fno-stack-protector",
             "-fno-asynchronous-unwind-tables", "-mno-red-zone", "-fno-common",
             "-nostdinc", "-I", sdk / "Headers", "-I", source_dir,
             "-isystem", resource / "include", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-Wno-unknown-warning-option", "-Wno-ossharedptr-misuse"]
    objects = []
    compile_commands = []
    for name in ("Probe.cpp", "module.cpp"):
        obj = staging / (Path(name).stem + ".o")
        args = [clang, *flags, "-c", source_dir / name, "-o", obj]
        command(args)
        objects.append(obj)
        compile_commands.append([str(a) for a in args])
    bundle = staging / (PRODUCT + ".kext")
    binary = bundle / "Contents" / "MacOS" / PRODUCT
    binary.parent.mkdir(parents=True)
    link_command = [linker, "-kext", "-arch", "x86_64", "-platform_version", "macos", "11.0", sdk_version,
                    "-undefined", "dynamic_lookup", "-o", binary, *objects,
                    sdk / "Library" / "x86_64" / "libkmod.a"]
    command(link_command)
    (bundle / "Contents" / "Info.plist").write_bytes((source_dir / "Info.plist").read_bytes())
    report = verify(bundle)
    report.update({"State": "BuiltFormatCheckedUninstalled", "Compiler": compiler_version,
                   "AppleLinker": linker, "SDKVersion": sdk_version,
                   "BuildScriptSHA256": sha256(Path(__file__).read_bytes()),
                   "CompileCommands": compile_commands, "LinkCommand": [str(a) for a in link_command],
                   "SigningPerformed": False, "InstallationPerformed": False,
                   "SecuritySettingsChanged": False, "USBChanged": False})
    symbols = {k: report["Binary"][k] for k in ("Imports", "Exports", "DefinedSymbols")}
    provenance = {"Source": source, "BuildScriptSHA256": report["BuildScriptSHA256"],
                  "Purpose": "Read-only PCI diagnostics; no display driver or firmware execution",
                  "RuntimeTested": False, "GraphicsBootVerified": False}
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    output = dist / (PRODUCT + "-UNTESTED.zip")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as result:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                result.write(path, path.relative_to(staging).as_posix())
        result.writestr("build-report.json", json.dumps(report, indent=2))
        result.writestr("symbols-manifest.json", json.dumps(symbols, indent=2))
        result.writestr("provenance.json", json.dumps(provenance, indent=2))
        result.writestr("LICENSE-MacKernelSDK.txt", SDK_LICENSE)
        for name, content in sorted(SOURCES.items()):
            result.writestr("source/" + name, content)
        result.write(Path(__file__), "source/build_diagnostic_probe.py")
    print(json.dumps({"Artifact": str(output), "ArtifactSHA256": sha256(output.read_bytes()),
                      "BinarySHA256": report["BinarySHA256"], "State": report["State"],
                      "RuntimeTested": False, "GraphicsBootVerified": False}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true", help="Read-only embedded source audit")
    parser.add_argument("--verify", type=Path, help="Extracted AD106DiagnosticProbe.kext; read-only")
    parser.add_argument("--boot-kc", type=Path)
    parser.add_argument("--nm", type=Path)
    args = parser.parse_args()
    if args.source_only:
        if args.verify or args.boot_kc or args.nm:
            parser.error("--source-only cannot be combined with binary audit options")
        print(json.dumps(source_report(), indent=2))
    elif args.verify:
        print(json.dumps(verify(args.verify, args.boot_kc, args.nm), indent=2))
    elif args.boot_kc or args.nm:
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
