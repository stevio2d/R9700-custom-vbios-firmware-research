# Firmware Security, Signatures and Write Protections


> This chapter separates inherited authentication claims from unverified board-specific behavior. No GPU-side VBIOS acceptance, enforced signature boundary or flashing result has been established here. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## The central feasibility question


Can the R9700 boot an arbitrarily modified VBIOS?

This has NOT been established by the available evidence.

## Distinct mechanisms to investigate

Software paths that look like reads may still trigger device or driver side
effects. Treat undocumented debugfs or mailbox interfaces as unsafe until their
behavior is established for the exact target kernel and firmware. The Python
capture CLI does not implement generic register, mailbox or SPI access. No
authentication bypass or image acceptance is established here.


1. PCI option-ROM checksums.
2. ATOM BIOS internal structure checks.
3. Cryptographic authentication of firmware regions.
4. GPU security processor or microcontroller validation.
5. Driver-level firmware validation.
6. Board and subsystem ID matching.
7. Software flasher model restrictions.
8. SPI status-register protection bits.
9. Hardware write-protect pin behavior.
10. Dual-BIOS support, if present on a specific PCB.

These are different mechanisms and require separate tests.

## Important limitations


A valid legacy checksum does not imply a valid signature.

A hardware SPI programmer may bypass a software write lock,
but it does not bypass a signature check performed at boot.

A ROM accepted by one board may be rejected by another because
of board ID, memory topology, display outputs or firmware policy.

## Research plan


- Compare original and official updated ASUS firmware.
- Identify every changed region.
- Search for authentication metadata and signature blocks.
- Compare behavior of signed and unsigned areas.
- Investigate AMD documentation and driver source code.
- Establish whether non-authenticated configuration data exists.
- Determine whether approved vendor firmware customization
  or runtime driver controls offer an alternative route.

## Stop condition


If the desired fields are covered by enforced signatures
and no legitimate signing route exists, do not claim that
a working arbitrary custom VBIOS is achievable.

Shift effort to supported tuning or vendor-provided firmware.

## Report evidence and unresolved boundaries


R1 says a 2020 AMDVBFlash guide shows RSA verification before programming. That is a lead about one utility path, not proof of exact R9700 whole-image authentication coverage. R2 explicitly finds no established universal signing model or community resigning tool. Both leave on-card boundaries unresolved. N's question therefore remains open: which bytes, if any, are mutable on this board and software stack?

Investigate transport/write acceptance separately from execution acceptance. Candidate enforcement layers include host flasher, option-ROM/UEFI loading, GPU security processor, embedded SMU firmware and OS driver. Identify what checks each component performs and when. A valid SHA-256 against a trusted reference establishes content identity; it is not itself a signing mechanism.

R1 describes unofficial AMDVBFlash 5.0.879 force/active-inactive features and says the associated publication calls it unauthorized and untested. Its mirrored-image claim requires R9700 evidence. R2 finds no documented EC-style lock or advertised dual-BIOS switch in its reviewed material. Absence from those sources does not establish absence on every board. No force switches, protection bypass or signing bypass are implemented here.

The static ASUS AS04/AS07 comparison found valid legacy byte-sum checksums and a PE certificate-table directory in each updater executable. The PE certificate directories were not validated, and they belong to the Windows update executables, not evidence of ROM authentication. Opaque payload ranges change between AS04 and AS07, but entropy or byte changes alone cannot identify signatures, signed regions, hashes or integrity coverage. No signed/unsigned boundary or accepted-image route was established; see the [ASUS analysis record](../bios/vendor-packages/asus/ASUS_ROM_ANALYSIS.md).

The static map now decompresses the bounded EFI option-ROM stream and validates the declared output length, AMD64 PE32+ headers, EFI boot-service-driver subsystem and section raw bounds. Applying linked Microsoft Authenticode procedure step 14 to the GOP PE yields candidate SHA-256 `77b66e1ac7a2fb9a6bc3cd695376ec055a7edd7378907b65d312406f3f6078f5`; its extra-data range is empty, and the raw candidate digest bytes occur in the bounded PKCS#7 record. This is a byte-stream calculation and raw occurrence check only: it does not parse the signed `SpcIndirectDataContent` or verify CMS, certificates, trust, or policy. This embedded GOP certificate table is separate from the PE certificate directories in the Windows updater executables. The code was not executed. None of these results reveal whether the GPU accepts a modified VBIOS or which firmware bytes are authenticated by GPU-side policy.

The ASUS UMC v4.0 table sets `umc_config1=0x00010000`, matching the public `UMC_CONFIG1__ENABLE_ECC_CAPABLE` definition. The Linux driver checks that bit when reporting VBIOS ECC capability, while separately tracking default ECC enablement in `umc_config`; this static bit is not a measurement of active correction or proof of ASUS runtime behavior. The XFX host log's ECC status remains XFX-only evidence.

The package's two Windows updater PE files have matching ZIP CRC-32 checks and measured member SHA-256 values; CRC-32 is only an accidental-corruption check. In both files the RAR5 archive marker is at `0x6b600`, exactly where the final declared PE section ends, and before the certificate table. The linked [Microsoft Authenticode PE procedure](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx) step 14 hashes extra file data beginning at `SUM_OF_BYTES_HASHED`; the calculated SHA-256 streams include the RAR5 overlays, and their raw digest values occur in the bounded PKCS#7 records. The current [Microsoft PE format page](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) contains conflicting prose that says post-section data is not hashed; this analysis follows the linked step-by-step procedure. No CMS signature, signer chain, timestamp, or trust policy was verified. These package results are separate from the embedded GOP certificate and GPU-side VBIOS authentication, and establish neither archive authenticity nor GPU acceptance.

## Future controlled acceptance experiment


Only after [demonstrated physical recovery](05_Flashing_Backup_and_Recovery.md) and a bounded structure/authentication map, select one non-critical, understood candidate field. “Single byte” from R1 means minimal scope, not an arbitrary offset: one semantic change may require a documented multi-byte field and understood integrity updates. Preserve all unrelated bytes and retain a full offset/old/new-byte record and parent/candidate hashes.

| Outcome | What it supports | What remains unresolved |
|---|---|---|
| Flasher refuses the file | A host-tool, format, compatibility or authentication restriction on that path | Exact check/reason; no conclusion yet about on-card authentication |
| Write verifies but the card fails initialization | Stored bytes alone are insufficient for acceptance | Authentication failure versus malformed structure, board mismatch or another firmware/driver incompatibility; retain logs and restore stock |
| Cold boot and driver initialization succeed, intended behavior changes | This particular edit appears accepted on this exact board/stack | Other regions, other boards and full stability still unproven |
| Boot succeeds but behavior does not change | The image may be loadable | Field interpretation, another active copy, driver override or SMU limit; do not claim a functional modification |

A failure alone does not isolate a signature boundary. A successful minimal edit does not establish arbitrary modification. Follow the [laboratory criteria](10_Laboratory_Test_Plan.md) and record inconclusive outcomes. If enforced signatures cover the intended change and no legitimate signing route exists, document that feasibility limit and shift to supported controls/vendor firmware.
