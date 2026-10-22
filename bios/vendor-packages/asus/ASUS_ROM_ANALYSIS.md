# ASUS R9700 ROM static analysis

> Read-only file analysis recorded 2026-10-19. The updater was not executed; the payloads are not associated with an identified physical ASUS card and are not established full-chip SPI images.

## Inputs and integrity

- Package: `bios/vendor-packages/asus/AI-PRO-R9700.zip` — 12,582,014 bytes, SHA-256 `cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0`.
- AS04: `bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS04.rom` — 2,031,872 bytes, SHA-256 `0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235`.
- AS07: `bios/vendor-packages/asus/payloads/7551OG.23.8.0.68.AS07.rom` — 2,031,872 bytes, SHA-256 `bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4`.
- Analyzer: `asus_rom_analysis.py 1.5.0` plus `tools/rom_triage.py`; JSON details are in [`ASUS_ROM_ANALYSIS.json`](ASUS_ROM_ANALYSIS.json).

The hashes match the previously recorded package and payload hashes. The package contains two AMD64 PE32+ GUI self-extractors. Static headers show an embedded RAR5 signature at file offset `0x6b600`; selected strings name `ASUSGraphicVBFlashTool.exe`, `amdvbflash.exe`, both BIOS members, and ASUS SFX settings. OpenSSL verifies each updater's PKCS#7 signer signature, and each signed SPC image digest matches the independently calculated Authenticode PE SHA-256. The PE hash ranges cover the RAR5 pre-certificate overlay. Certificate-chain trust, timestamps and Windows policy were not checked. No executable was launched.

## Image and code map

Each payload is `0x1f0100` bytes. The bounded PCIR chains are repeated exactly at `0x40000–0x5ca00` and `0x120000–0x13ca00` within each file. That duplication alone does not establish a dual-BIOS topology, a recovery bank, or full-chip coverage.

### Package member integrity and updater overlay geometry

| Member | Declared CRC32 | Computed CRC32 | CRC status | Member SHA-256 |
|---|---|---|---|---|
| `AI-PRO-R9700_default.exe` | `0x24d365be` | `0x24d365be` | match | `79cee792a0a73dfe0a7bc884256046b54cbd7aa6cfbffefbf88ee98da37a9dc2` |
| `AI-PRO-R9700_update.exe` | `0x86571ba5` | `0x86571ba5` | match | `4daa72acffe1d72353fe117ffe9ddad7a463b848f34b585fcb7cd45f3937ee4f` |

ZIP CRC-32 matches are corruption checks, not cryptographic authentication. For each updater, the table below compares the embedded RAR5 marker to the last declared PE section and certificate-table boundaries:

| Updater | Last section raw end | RAR5 offset | First overlay byte | Certificate range | SHA-256 coverage result |
|---|---:|---:|---|---|---|
| `AI-PRO-R9700_default.exe` | `0x6b600` | `0x6b600` | true | `0x62dd90+0x29a0` | PKCS#7 signer signature verified; signed SPC digest matches calculated PE SHA-256; overlay covered.
| `AI-PRO-R9700_update.exe` | `0x6b600` | `0x6b600` | true | `0x634f70+0x29a0` | PKCS#7 signer signature verified; signed SPC digest matches calculated PE SHA-256; overlay covered.

The calculated SHA-256 stream follows the linked Microsoft Authenticode_PE step 14 formula: bytes beginning at `SUM_OF_BYTES_HASHED` are included up to the certificate-table size exclusion. OpenSSL verifies the PKCS#7 signer signature, and the signed SPC SHA-256 matches the calculated PE digest, whose range covers the RAR5 marker and pre-certificate overlay. `-noverify` skips signer-certificate chain validation; timestamps and Windows policy were not evaluated. The Learn PE page's general prose about post-section bytes conflicts with this linked procedure, so the step-by-step procedure is used here. This updater signature result does not establish archive behavior or GPU-side VBIOS acceptance.

### PCIR image chain

| Offset | Length | PCIR code type | PCI IDs | Findings |
|---|---:|---:|---|---|
| `0x40000–0x4e600` | 58,880 | `0` | `1002:7551` | Legacy option-ROM; checksum is valid; Ghidra recovered 244 functions and 674 direct-call sites. |
| `0x4e600–0x5ca00` | 58,368 | `3` | `1002:7551` | EFI image signature `0x0ef1`, x64 machine `0x8664`, compression type 1; `GOP AMD REV: 003.009.001.023.008` at `0x4e634`. compressed stream identified and PE validated. Compressed stream: 57,824 bytes; declared output: 100,560 bytes; zero terminator valid; SHA-256 `d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11`. EDK II TianoCompress produced a 100,560-byte AMD64 PE image (subsystem: EFI boot service driver; entry RVA 0x354; 5 bounded sections; output SHA-256 `77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b`). 440 bytes of `0xff` end padding are identified. |
| `0x120000–0x12e600` | 58,880 | `0` | `1002:7551` | Legacy option-ROM; checksum is valid; Ghidra recovered 244 functions and 674 direct-call sites. |
| `0x12e600–0x13ca00` | 58,368 | `3` | `1002:7551` | EFI image signature `0x0ef1`, x64 machine `0x8664`, compression type 1; `GOP AMD REV: 003.009.001.023.008` at `0x12e634`. compressed stream identified and PE validated. Compressed stream: 57,824 bytes; declared output: 100,560 bytes; zero terminator valid; SHA-256 `d1eeeeb544af7486cbec12e03c4f6c553eb518dac693e93ed85d0dc51d825c11`. EDK II TianoCompress produced a 100,560-byte AMD64 PE image (subsystem: EFI boot service driver; entry RVA 0x354; 5 bounded sections; output SHA-256 `77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b`). 440 bytes of `0xff` end padding are identified. |

UEFI defines code type 0x03 as EFI, compression type 0x0001 as compressed, and requires each option-ROM image to be padded to a multiple of 512 bytes. The bounded 8-byte envelope, declared output size, zero terminator, and compressed-stream hash were checked. EDK II TianoCompress decompressed the stream; the result passed bounded PE/COFF, AMD64, EFI boot-service-driver, and section-range checks. The output was never loaded or executed. The GOP revision string is before the EFI image payload offset 0x60, so it is not a code-path finding. PE signature verification is described below and does not establish GPU-side image authentication. See [UEFI 2.10, PCI bus support](https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html) and the [UEFI compression algorithm specification](https://uefi.org/specs/UEFI/2.10_A/19_Protocols_Compression_Algorithm_Specification.html).

### Visible strings

- **VBIOS part:** AS04: `0x40070–0x40080`: `115-G287BP00-100`; `0x120070–0x120080`: `115-G287BP00-100`; AS07: `0x40070–0x40080`: `115-G287BP00-100`; `0x120070–0x120080`: `115-G287BP00-100`
- **ASUS ROM version:** AS04: `0x400a0–0x400ec`: `7551OG.23.8.0.68.AS04`; `0x1200a0–0x1200ec`: `7551OG.23.8.0.68.AS04`; AS07: `0x400a0–0x400ec`: `7551OG.23.8.0.68.AS07`; `0x1200a0–0x1200ec`: `7551OG.23.8.0.68.AS07`
- **ATOM BIOS version:** AS04: `0x40121–0x40149`: `ATOMBIOSBK-AMD VER023.008.000.068.000001`; `0x120121–0x120149`: `ATOMBIOSBK-AMD VER023.008.000.068.000001`; AS07: `0x40121–0x40149`: `ATOMBIOSBK-AMD VER023.008.000.068.000001`; `0x120121–0x120149`: `ATOMBIOSBK-AMD VER023.008.000.068.000001`
- **Board string:** AS04: `0x40172–0x40198`: `ASUS_G28702_XTW_32GB_PS_APM108117_300W`; `0x120172–0x120198`: `ASUS_G28702_XTW_32GB_PS_APM108117_300W`; AS07: `0x40172–0x40198`: `ASUS_G28702_XTW_32GB_PS_APM108117_300W`; `0x120172–0x120198`: `ASUS_G28702_XTW_32GB_PS_APM108117_300W`
- **GOP revision string:** AS04: `0x4e634–0x4e654`: `GOP AMD REV: 003.009.001.023.008`; `0x12e634–0x12e654`: `GOP AMD REV: 003.009.001.023.008`; AS07: `0x4e634–0x4e654`: `GOP AMD REV: 003.009.001.023.008`; `0x12e634–0x12e654`: `GOP AMD REV: 003.009.001.023.008`
- **Timestamp strings:** AS04: `0x37fa0–0x37fb1`: `03/17/26,22:38:29`; `0x40050–0x40061`: `03/17/26,22:38:29`; `0x43220–0x43231`: `03/17/26,22:38:29`; `0xa86a0–0xa86b1`: `01/16/25,00:53:49`; `0x117fa0–0x117fb1`: `03/17/26,22:38:29`; `0x120050–0x120061`: `03/17/26,22:38:29`; `0x123220–0x123231`: `03/17/26,22:38:29`; `0x1886a0–0x1886b1`: `01/16/25,00:53:49`; AS07: `0x37fa0–0x37fb1`: `05/07/26,23:10:43`; `0x40050–0x40061`: `05/07/26,23:10:43`; `0x43220–0x43231`: `05/07/26,23:10:43`; `0xa86a0–0xa86b1`: `01/16/25,00:53:49`; `0x117fa0–0x117fb1`: `05/07/26,23:10:43`; `0x120050–0x120061`: `05/07/26,23:10:43`; `0x123220–0x123231`: `05/07/26,23:10:43`; `0x1886a0–0x1886b1`: `01/16/25,00:53:49`
- **Product string:** AS04: `0x1f0023–0x1f0035`: `TURBO-AI-PRO-R9700`; AS07: `0x1f0023–0x1f0035`: `TURBO-AI-PRO-R9700`

### Embedded GOP PE static inspection

The decompressed image is PE32+ `AMD64`, entry RVA `0x354`, image size 90,784 bytes, and EFI boot-service-driver subsystem. Its 5 section raw ranges are bounded:

| Section | RVA | Raw offset | Raw size | Flags |
|---|---:|---:|---:|---|
| `.text` | `0x2a0` | `0x2a0` | 73,408 | R, X |
| `.data` | `0x12160` | `0x12160` | 11,584 | R, W |
| `.pdata` | `0x14ea0` | `0x14ea0` | 2,784 | R |
| `.xdata` | `0x15980` | `0x15980` | 1,664 | R |
| `.reloc` | `0x16000` | `0x16000` | 672 | R |

The PE import directory is zero/zero (no conventional imports declared). The certificate directory is at file offset `0x162a0`, length 9,776, with PKCS_SIGNED_DATA; its table SHA-256 is `67e018d45451126efc5174c0f1adbd88c8c58643c804f4c3ad518e15de0b70ee`. Applying [Microsoft Authenticode procedure step 14](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx) yields candidate SHA-256 `77b66e1ac7a2fb9a6bc3cd695376ec055a7edd7378907b65d312406f3f6078f5` with extra-data range `0x162a0–0x162a0` (0 bytes). OpenSSL verification status is `pkcs7_signer_signature_and_pe_image_digest_verified`; the signed SPC SHA-256 matches the calculated PE digest. Signer-certificate chain validation, timestamp and Windows trust policy were not performed.

Ghidra 12.1.4 analyzed the exact output SHA-256 `77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b` statically. Ghidra identified 254 functions (4 non-default names); the entry routine has 199 addresses. This is a disassembly/decompilation view, not a runtime trace.

#### Recovered function inventory

All Ghidra-recovered functions are listed below. `Entry depth` is the shortest path from the PE entry through statically resolved direct calls; computed calls do not contribute to this graph. `Data refs` retains all static data references, including stack references; the separate reachable-global table includes only references mapped to program memory. `—` means no direct-call path was recovered.

| Entry | Function | Body address count | Thunk | Direct call sites | Indirect/unresolved calls | Function xrefs | Data refs | Entry depth |
|---:|---|---:|---|---:|---:|---:|---:|---:|
| `000002a0` | `FUN_000002a0` | 178 | false | 0 | 2 | 3 | 20 | — |
| `00000354` | `entry` | 199 | false | 1 | 3 | 3 | 25 | 0 |
| `0000041c` | `FUN_0000041c` | 188 | false | 1 | 5 | 2 | 18 | 1 |
| `000004d8` | `FUN_000004d8` | 185 | false | 6 | 0 | 1 | 11 | — |
| `00000594` | `FUN_00000594` | 93 | false | 3 | 0 | 1 | 2 | — |
| `000005f4` | `FUN_000005f4` | 606 | false | 4 | 4 | 2 | 31 | — |
| `00000854` | `FUN_00000854` | 2093 | false | 65 | 10 | 2 | 61 | — |
| `00001084` | `FUN_00001084` | 467 | false | 11 | 4 | 2 | 17 | — |
| `00001258` | `FUN_00001258` | 353 | false | 0 | 9 | 4 | 26 | — |
| `000013bc` | `FUN_000013bc` | 595 | false | 3 | 8 | 7 | 26 | — |
| `00001610` | `FUN_00001610` | 932 | false | 12 | 7 | 4 | 44 | — |
| `000019b4` | `FUN_000019b4` | 95 | false | 1 | 1 | 3 | 6 | — |
| `00001a14` | `FUN_00001a14` | 190 | false | 3 | 1 | 3 | 4 | — |
| `00001ad4` | `FUN_00001ad4` | 97 | false | 0 | 0 | 2 | 0 | — |
| `00001b38` | `FUN_00001b38` | 69 | false | 0 | 0 | 9 | 0 | — |
| `00001b80` | `FUN_00001b80` | 309 | false | 8 | 2 | 2 | 19 | — |
| `00001cb8` | `FUN_00001cb8` | 758 | false | 6 | 3 | 2 | 39 | — |
| `00001fb0` | `FUN_00001fb0` | 1339 | false | 34 | 7 | 2 | 43 | — |
| `000024ec` | `FUN_000024ec` | 1034 | false | 4 | 0 | 2 | 120 | — |
| `000028f8` | `FUN_000028f8` | 168 | false | 1 | 0 | 3 | 6 | — |
| `000029a0` | `FUN_000029a0` | 121 | false | 3 | 0 | 4 | 6 | — |
| `00002a1c` | `FUN_00002a1c` | 75 | false | 0 | 0 | 3 | 0 | — |
| `00002a68` | `FUN_00002a68` | 53 | false | 0 | 1 | 6 | 1 | — |
| `00002aa0` | `FUN_00002aa0` | 303 | false | 2 | 2 | 4 | 15 | — |
| `00002bd0` | `FUN_00002bd0` | 541 | false | 0 | 4 | 3 | 72 | — |
| `00002df0` | `FUN_00002df0` | 240 | false | 5 | 0 | 2 | 8 | — |
| `00002ee0` | `FUN_00002ee0` | 334 | false | 0 | 0 | 3 | 29 | — |
| `00003030` | `FUN_00003030` | 180 | false | 7 | 0 | 3 | 8 | — |
| `000030e4` | `FUN_000030e4` | 491 | false | 17 | 0 | 2 | 15 | — |
| `000032d0` | `FUN_000032d0` | 268 | false | 16 | 0 | 2 | 7 | — |
| `000033dc` | `FUN_000033dc` | 169 | false | 10 | 0 | 2 | 4 | — |
| `00003488` | `FUN_00003488` | 200 | false | 6 | 0 | 4 | 13 | — |
| `00003550` | `FUN_00003550` | 85 | false | 3 | 0 | 3 | 4 | — |
| `000035a8` | `FUN_000035a8` | 223 | false | 4 | 2 | 2 | 8 | — |
| `00003688` | `FUN_00003688` | 38 | false | 2 | 0 | 60 | 0 | — |
| `000036b0` | `FUN_000036b0` | 77 | false | 2 | 0 | 50 | 3 | — |
| `00003700` | `FUN_00003700` | 52 | false | 0 | 0 | 5 | 4 | — |
| `00003734` | `FUN_00003734` | 198 | false | 5 | 0 | 9 | 12 | — |
| `000037fc` | `FUN_000037fc` | 129 | false | 4 | 0 | 9 | 10 | — |
| `00003880` | `FUN_00003880` | 103 | false | 1 | 0 | 8 | 10 | — |
| `000038e8` | `FUN_000038e8` | 428 | false | 13 | 0 | 2 | 15 | — |
| `00003a94` | `FUN_00003a94` | 154 | false | 6 | 0 | 6 | 4 | — |
| `00003b30` | `FUN_00003b30` | 44 | false | 2 | 0 | 6 | 0 | — |
| `00003b5c` | `FUN_00003b5c` | 159 | false | 4 | 0 | 3 | 11 | — |
| `00003bfc` | `FUN_00003bfc` | 936 | false | 26 | 2 | 2 | 30 | — |
| `00003fa4` | `FUN_00003fa4` | 100 | false | 2 | 0 | 3 | 0 | — |
| `00004008` | `FUN_00004008` | 50 | false | 1 | 0 | 8 | 6 | — |
| `0000403c` | `FUN_0000403c` | 115 | false | 1 | 0 | 7 | 10 | — |
| `000040b0` | `FUN_000040b0` | 106 | false | 1 | 0 | 3 | 9 | — |
| `0000411c` | `FUN_0000411c` | 322 | false | 14 | 0 | 2 | 8 | — |
| `00004260` | `FUN_00004260` | 213 | false | 7 | 0 | 2 | 9 | — |
| `00004338` | `FUN_00004338` | 102 | false | 3 | 0 | 7 | 2 | — |
| `000043a0` | `FUN_000043a0` | 642 | false | 12 | 0 | 2 | 9 | — |
| `00004624` | `FUN_00004624` | 408 | false | 12 | 0 | 2 | 6 | — |
| `000047bc` | `FUN_000047bc` | 111 | false | 2 | 0 | 3 | 2 | — |
| `0000482c` | `FUN_0000482c` | 113 | false | 1 | 0 | 4 | 2 | — |
| `000048a0` | `FUN_000048a0` | 80 | false | 1 | 0 | 3 | 0 | — |
| `000048f0` | `FUN_000048f0` | 444 | false | 7 | 0 | 2 | 8 | — |
| `00004aac` | `FUN_00004aac` | 253 | false | 1 | 0 | 16 | 1 | — |
| `00004bac` | `FUN_00004bac` | 73 | false | 2 | 0 | 6 | 2 | — |
| `00004bf8` | `FUN_00004bf8` | 50 | false | 2 | 0 | 10 | 0 | — |
| `00004c2c` | `FUN_00004c2c` | 190 | false | 2 | 0 | 2 | 6 | — |
| `00004cec` | `FUN_00004cec` | 168 | false | 2 | 0 | 15 | 6 | — |
| `00004d94` | `FUN_00004d94` | 1297 | false | 23 | 0 | 2 | 10 | — |
| `000052a8` | `FUN_000052a8` | 183 | false | 2 | 0 | 2 | 4 | — |
| `00005360` | `FUN_00005360` | 221 | false | 1 | 0 | 3 | 0 | — |
| `00005440` | `FUN_00005440` | 54 | false | 1 | 0 | 2 | 3 | — |
| `00005478` | `FUN_00005478` | 346 | false | 1 | 0 | 2 | 20 | — |
| `000055d4` | `FUN_000055d4` | 521 | false | 3 | 4 | 2 | 22 | — |
| `000057e0` | `FUN_000057e0` | 415 | false | 0 | 0 | 2 | 26 | — |
| `0000598c` | `FUN_0000598c` | 537 | false | 4 | 0 | 2 | 42 | — |
| `00005ba8` | `FUN_00005ba8` | 92 | false | 0 | 0 | 2 | 0 | — |
| `00005c04` | `FUN_00005c04` | 167 | false | 1 | 1 | 2 | 17 | — |
| `00005cac` | `FUN_00005cac` | 357 | false | 2 | 0 | 3 | 9 | — |
| `00005e14` | `FUN_00005e14` | 119 | false | 0 | 0 | 3 | 0 | — |
| `00005e8c` | `FUN_00005e8c` | 119 | false | 0 | 0 | 5 | 0 | — |
| `00005f04` | `FUN_00005f04` | 49 | false | 1 | 0 | 105 | 1 | — |
| `00005f38` | `FUN_00005f38` | 70 | false | 1 | 0 | 3 | 1 | — |
| `00005f80` | `FUN_00005f80` | 183 | false | 1 | 0 | 2 | 6 | — |
| `00006038` | `FUN_00006038` | 103 | false | 1 | 0 | 4 | 0 | — |
| `000060a0` | `FUN_000060a0` | 97 | false | 1 | 0 | 5 | 6 | — |
| `00006104` | `FUN_00006104` | 93 | false | 1 | 0 | 5 | 2 | — |
| `00006164` | `FUN_00006164` | 406 | false | 3 | 0 | 4 | 8 | — |
| `000062fc` | `FUN_000062fc` | 101 | false | 1 | 0 | 3 | 0 | — |
| `00006364` | `FUN_00006364` | 107 | false | 2 | 0 | 5 | 2 | — |
| `000063d0` | `FUN_000063d0` | 181 | false | 2 | 0 | 6 | 6 | — |
| `00006488` | `FUN_00006488` | 234 | false | 10 | 0 | 2 | 2 | — |
| `00006574` | `FUN_00006574` | 79 | false | 1 | 0 | 3 | 1 | — |
| `000065c4` | `FUN_000065c4` | 86 | false | 4 | 0 | 3 | 2 | — |
| `0000661c` | `FUN_0000661c` | 195 | false | 0 | 0 | 3 | 2 | — |
| `000066e0` | `FUN_000066e0` | 395 | false | 7 | 0 | 4 | 6 | — |
| `0000686c` | `FUN_0000686c` | 293 | false | 5 | 0 | 5 | 7 | — |
| `00006994` | `FUN_00006994` | 169 | false | 0 | 0 | 2 | 0 | — |
| `00006a40` | `FUN_00006a40` | 1071 | false | 17 | 0 | 5 | 10 | — |
| `00006e70` | `FUN_00006e70` | 192 | false | 4 | 0 | 2 | 2 | — |
| `00006f30` | `FUN_00006f30` | 1664 | false | 0 | 0 | 2 | 184 | — |
| `000075b0` | `FUN_000075b0` | 1218 | false | 7 | 0 | 4 | 40 | — |
| `00007a74` | `FUN_00007a74` | 555 | false | 0 | 0 | 3 | 8 | — |
| `00007ca0` | `FUN_00007ca0` | 1466 | false | 3 | 0 | 3 | 6 | — |
| `0000825c` | `FUN_0000825c` | 204 | false | 0 | 0 | 2 | 2 | — |
| `00008328` | `FUN_00008328` | 423 | false | 0 | 0 | 3 | 2 | — |
| `000084d0` | `FUN_000084d0` | 359 | false | 1 | 3 | 2 | 25 | — |
| `00008638` | `FUN_00008638` | 454 | false | 5 | 7 | 2 | 26 | — |
| `00008800` | `FUN_00008800` | 306 | false | 2 | 5 | 2 | 17 | — |
| `00008934` | `FUN_00008934` | 335 | false | 1 | 4 | 3 | 33 | — |
| `00008a84` | `FUN_00008a84` | 528 | false | 1 | 5 | 3 | 20 | — |
| `00008c94` | `FUN_00008c94` | 455 | false | 0 | 1 | 3 | 16 | — |
| `00008e5c` | `FUN_00008e5c` | 242 | false | 0 | 2 | 3 | 36 | — |
| `00008f50` | `FUN_00008f50` | 55 | false | 0 | 1 | 8 | 3 | — |
| `00008f88` | `FUN_00008f88` | 369 | false | 3 | 5 | 6 | 16 | — |
| `000090fc` | `FUN_000090fc` | 365 | false | 5 | 3 | 8 | 19 | — |
| `0000926c` | `FUN_0000926c` | 67 | false | 1 | 0 | 5 | 3 | — |
| `000092b0` | `FUN_000092b0` | 149 | false | 2 | 0 | 3 | 16 | — |
| `00009348` | `FUN_00009348` | 380 | false | 1 | 1 | 5 | 24 | — |
| `000094c4` | `FUN_000094c4` | 137 | false | 2 | 0 | 2 | 19 | — |
| `00009550` | `FUN_00009550` | 333 | false | 2 | 2 | 5 | 13 | — |
| `000096a0` | `FUN_000096a0` | 221 | false | 2 | 1 | 3 | 17 | — |
| `00009780` | `FUN_00009780` | 512 | false | 10 | 0 | 3 | 25 | — |
| `00009980` | `FUN_00009980` | 3448 | false | 42 | 13 | 3 | 174 | — |
| `0000a6f8` | `FUN_0000a6f8` | 626 | false | 9 | 4 | 2 | 15 | — |
| `0000a96c` | `FUN_0000a96c` | 117 | false | 0 | 3 | 3 | 3 | — |
| `0000a9e4` | `FUN_0000a9e4` | 177 | false | 0 | 0 | 2 | 0 | — |
| `0000aa98` | `FUN_0000aa98` | 388 | false | 17 | 1 | 2 | 2 | — |
| `0000ac1c` | `FUN_0000ac1c` | 218 | false | 3 | 0 | 4 | 28 | — |
| `0000acf8` | `FUN_0000acf8` | 236 | false | 3 | 0 | 6 | 22 | — |
| `0000ade4` | `FUN_0000ade4` | 367 | false | 4 | 0 | 3 | 49 | — |
| `0000af54` | `FUN_0000af54` | 368 | false | 4 | 0 | 2 | 49 | — |
| `0000b0c4` | `FUN_0000b0c4` | 264 | false | 3 | 0 | 3 | 33 | — |
| `0000b1cc` | `FUN_0000b1cc` | 438 | false | 4 | 0 | 4 | 10 | — |
| `0000b384` | `FUN_0000b384` | 334 | false | 7 | 0 | 2 | 30 | — |
| `0000b4d4` | `FUN_0000b4d4` | 311 | false | 3 | 3 | 2 | 28 | — |
| `0000b60c` | `FUN_0000b60c` | 308 | false | 3 | 3 | 2 | 28 | — |
| `0000b740` | `FUN_0000b740` | 67 | false | 0 | 1 | 5 | 4 | — |
| `0000b784` | `FUN_0000b784` | 71 | false | 0 | 1 | 4 | 4 | — |
| `0000b7cc` | `FUN_0000b7cc` | 69 | false | 0 | 1 | 2 | 4 | — |
| `0000b814` | `FUN_0000b814` | 53 | false | 0 | 1 | 5 | 1 | — |
| `0000b84c` | `FUN_0000b84c` | 55 | false | 0 | 1 | 4 | 1 | — |
| `0000b884` | `FUN_0000b884` | 55 | false | 0 | 1 | 2 | 1 | — |
| `0000b8bc` | `FUN_0000b8bc` | 74 | false | 0 | 1 | 5 | 5 | — |
| `0000b908` | `FUN_0000b908` | 77 | false | 0 | 1 | 4 | 5 | — |
| `0000b958` | `FUN_0000b958` | 77 | false | 0 | 1 | 2 | 5 | — |
| `0000b9a8` | `FUN_0000b9a8` | 59 | false | 0 | 1 | 5 | 2 | — |
| `0000b9e4` | `FUN_0000b9e4` | 60 | false | 0 | 1 | 4 | 2 | — |
| `0000ba20` | `FUN_0000ba20` | 62 | false | 0 | 1 | 2 | 2 | — |
| `0000ba60` | `FUN_0000ba60` | 54 | false | 1 | 0 | 1 | 3 | — |
| `0000bab0` | `FUN_0000bab0` | 101 | false | 0 | 0 | 1 | 0 | — |
| `0000bb18` | `FUN_0000bb18` | 101 | false | 0 | 0 | 2 | 0 | — |
| `0000bb80` | `FUN_0000bb80` | 94 | false | 4 | 0 | 4 | 5 | — |
| `0000bbe0` | `FUN_0000bbe0` | 1203 | false | 27 | 0 | 2 | 64 | — |
| `0000c094` | `FUN_0000c094` | 826 | false | 15 | 0 | 16 | 28 | — |
| `0000c3d0` | `FUN_0000c3d0` | 889 | false | 11 | 0 | 2 | 17 | — |
| `0000c74c` | `FUN_0000c74c` | 102 | false | 1 | 0 | 4 | 7 | — |
| `0000c7b4` | `FUN_0000c7b4` | 86 | false | 1 | 0 | 3 | 5 | — |
| `0000c80c` | `FUN_0000c80c` | 128 | false | 1 | 0 | 4 | 6 | — |
| `0000c88c` | `FUN_0000c88c` | 460 | false | 1 | 0 | 4 | 15 | — |
| `0000ca58` | `FUN_0000ca58` | 229 | false | 1 | 0 | 4 | 14 | — |
| `0000cb40` | `FUN_0000cb40` | 50 | false | 0 | 0 | 16 | 0 | — |
| `0000cb74` | `FUN_0000cb74` | 77 | false | 1 | 0 | 11 | 2 | — |
| `0000cbc4` | `FUN_0000cbc4` | 73 | false | 1 | 0 | 3 | 0 | — |
| `0000cc10` | `FUN_0000cc10` | 76 | false | 1 | 0 | 3 | 0 | — |
| `0000cc5c` | `FUN_0000cc5c` | 73 | false | 1 | 0 | 4 | 0 | — |
| `0000cca8` | `FUN_0000cca8` | 41 | false | 1 | 0 | 13 | 0 | — |
| `0000ccd4` | `FUN_0000ccd4` | 426 | false | 8 | 0 | 3 | 6 | — |
| `0000ce80` | `FUN_0000ce80` | 469 | false | 0 | 0 | 2 | 8 | — |
| `0000d058` | `FUN_0000d058` | 301 | false | 1 | 0 | 2 | 2 | — |
| `0000d188` | `FUN_0000d188` | 218 | false | 2 | 0 | 2 | 7 | — |
| `0000d264` | `FUN_0000d264` | 103 | false | 2 | 0 | 3 | 2 | — |
| `0000d2cc` | `FUN_0000d2cc` | 93 | false | 1 | 0 | 2 | 0 | — |
| `0000d32c` | `FUN_0000d32c` | 47 | false | 1 | 0 | 18 | 3 | — |
| `0000d35c` | `FUN_0000d35c` | 339 | false | 3 | 0 | 5 | 24 | — |
| `0000d4b0` | `FUN_0000d4b0` | 165 | false | 2 | 0 | 4 | 9 | — |
| `0000d558` | `FUN_0000d558` | 585 | false | 1 | 2 | 2 | 49 | — |
| `0000d7a4` | `FUN_0000d7a4` | 877 | false | 8 | 1 | 2 | 40 | — |
| `0000dc64` | `FUN_0000dc64` | 174 | false | 0 | 1 | 3 | 8 | — |
| `0000dd14` | `caseD_0` | 152 | false | 2 | 2 | 13 | 0 | — |
| `0000de80` | `caseD_6` | 153 | false | 2 | 2 | 14 | 3 | — |
| `0000dfbc` | `caseD_9` | 67 | false | 1 | 0 | 14 | 3 | — |
| `0000e0ac` | `FUN_0000e0ac` | 62 | false | 0 | 2 | 14 | 2 | — |
| `0000e0ec` | `FUN_0000e0ec` | 193 | false | 0 | 3 | 1 | 8 | — |
| `0000e1b0` | `FUN_0000e1b0` | 211 | false | 0 | 3 | 1 | 11 | — |
| `0000e284` | `FUN_0000e284` | 105 | false | 1 | 0 | 1 | 5 | — |
| `0000e2f0` | `FUN_0000e2f0` | 620 | false | 2 | 0 | 1 | 6 | — |
| `0000e354` | `FUN_0000e354` | 99 | false | 1 | 0 | 1 | 4 | — |
| `0000e3b8` | `FUN_0000e3b8` | 164 | false | 1 | 0 | 1 | 9 | — |
| `0000e45c` | `FUN_0000e45c` | 164 | false | 1 | 0 | 1 | 9 | — |
| `0000e500` | `FUN_0000e500` | 162 | false | 1 | 0 | 1 | 9 | — |
| `0000e5a4` | `FUN_0000e5a4` | 162 | false | 1 | 0 | 1 | 9 | — |
| `0000e648` | `FUN_0000e648` | 92 | false | 1 | 0 | 1 | 4 | — |
| `0000e6a4` | `FUN_0000e6a4` | 96 | false | 1 | 0 | 1 | 4 | — |
| `0000e704` | `FUN_0000e704` | 107 | false | 1 | 0 | 1 | 4 | — |
| `0000e770` | `FUN_0000e770` | 104 | false | 1 | 0 | 1 | 4 | — |
| `0000e7d8` | `FUN_0000e7d8` | 105 | false | 1 | 0 | 1 | 4 | — |
| `0000e844` | `FUN_0000e844` | 94 | false | 0 | 1 | 1 | 5 | — |
| `0000e8a4` | `FUN_0000e8a4` | 165 | false | 0 | 1 | 1 | 7 | — |
| `0000e94c` | `FUN_0000e94c` | 99 | false | 1 | 0 | 1 | 4 | — |
| `0000e9b0` | `FUN_0000e9b0` | 73 | false | 0 | 1 | 3 | 4 | — |
| `0000e9fc` | `FUN_0000e9fc` | 28 | false | 1 | 0 | 1 | 0 | — |
| `0000ea18` | `FUN_0000ea18` | 160 | false | 1 | 1 | 1 | 3 | — |
| `0000eb68` | `FUN_0000eb68` | 52 | false | 1 | 0 | 1 | 0 | — |
| `0000eb9c` | `FUN_0000eb9c` | 46 | false | 1 | 0 | 1 | 0 | — |
| `0000ed08` | `FUN_0000ed08` | 77 | false | 1 | 0 | 2 | 5 | — |
| `0000ed58` | `FUN_0000ed58` | 74 | false | 0 | 0 | 1 | 3 | — |
| `0000eda4` | `FUN_0000eda4` | 50 | false | 0 | 0 | 3 | 0 | — |
| `0000edd8` | `FUN_0000edd8` | 118 | false | 0 | 0 | 13 | 0 | — |
| `0000ee50` | `FUN_0000ee50` | 451 | false | 0 | 0 | 10 | 0 | — |
| `0000f014` | `FUN_0000f014` | 50 | false | 1 | 0 | 4 | 5 | — |
| `0000f048` | `FUN_0000f048` | 51 | false | 0 | 0 | 4 | 2 | — |
| `0000f07c` | `FUN_0000f07c` | 3918 | false | 7 | 0 | 5 | 191 | — |
| `0000ffcc` | `FUN_0000ffcc` | 34 | false | 1 | 0 | 4 | 4 | — |
| `0000fff0` | `FUN_0000fff0` | 46 | false | 0 | 1 | 13 | 3 | — |
| `00010020` | `FUN_00010020` | 52 | false | 2 | 0 | 12 | 0 | — |
| `00010054` | `FUN_00010054` | 72 | false | 2 | 0 | 5 | 2 | — |
| `0001009c` | `FUN_0001009c` | 123 | false | 2 | 1 | 2 | 7 | — |
| `00010118` | `FUN_00010118` | 75 | false | 1 | 0 | 6 | 0 | — |
| `00010164` | `FUN_00010164` | 254 | false | 9 | 0 | 2 | 10 | — |
| `00010264` | `FUN_00010264` | 231 | false | 6 | 1 | 2 | 13 | — |
| `0001034c` | `FUN_0001034c` | 65 | false | 0 | 0 | 3 | 0 | — |
| `00010390` | `FUN_00010390` | 178 | false | 3 | 0 | 109 | 9 | — |
| `00010470` | `FUN_00010470` | 38 | false | 1 | 0 | 2 | 2 | — |
| `00010498` | `FUN_00010498` | 800 | false | 10 | 0 | 1 | 56 | — |
| `000107e0` | `FUN_000107e0` | 186 | false | 2 | 0 | 1 | 8 | — |
| `0001089c` | `FUN_0001089c` | 481 | false | 8 | 0 | 1 | 36 | — |
| `00010a80` | `FUN_00010a80` | 128 | false | 3 | 0 | 1 | 7 | — |
| `00010b00` | `FUN_00010b00` | 97 | false | 2 | 0 | 1 | 9 | — |
| `00010b90` | `FUN_00010b90` | 153 | false | 5 | 0 | 1 | 11 | — |
| `00010c2c` | `FUN_00010c2c` | 368 | false | 9 | 0 | 1 | 28 | — |
| `00010d9c` | `FUN_00010d9c` | 123 | false | 1 | 0 | 1 | 12 | — |
| `00010e80` | `FUN_00010e80` | 142 | false | 2 | 0 | 1 | 9 | — |
| `00010f24` | `FUN_00010f24` | 422 | false | 4 | 0 | 1 | 25 | — |
| `000110cc` | `FUN_000110cc` | 39 | false | 1 | 0 | 1 | 2 | — |
| `00011104` | `FUN_00011104` | 135 | false | 3 | 0 | 1 | 9 | — |
| `0001118c` | `FUN_0001118c` | 242 | false | 1 | 0 | 5 | 22 | — |
| `00011280` | `FUN_00011280` | 381 | false | 12 | 0 | 1 | 29 | — |
| `00011400` | `FUN_00011400` | 258 | false | 10 | 0 | 1 | 14 | — |
| `00011504` | `FUN_00011504` | 56 | false | 1 | 0 | 1 | 4 | — |
| `0001153c` | `FUN_0001153c` | 285 | false | 6 | 0 | 1 | 14 | — |
| `0001165c` | `FUN_0001165c` | 248 | false | 5 | 0 | 1 | 26 | — |
| `00011768` | `FUN_00011768` | 76 | false | 1 | 0 | 1 | 5 | — |
| `000117b4` | `FUN_000117b4` | 67 | false | 2 | 0 | 1 | 5 | — |
| `000117f8` | `FUN_000117f8` | 87 | false | 1 | 0 | 1 | 6 | — |
| `00011850` | `FUN_00011850` | 204 | false | 5 | 0 | 1 | 12 | — |
| `0001191c` | `FUN_0001191c` | 132 | false | 3 | 0 | 1 | 8 | — |
| `000119a0` | `FUN_000119a0` | 136 | false | 3 | 0 | 1 | 10 | — |
| `00011a28` | `FUN_00011a28` | 57 | false | 2 | 0 | 1 | 3 | — |
| `00011ab8` | `FUN_00011ab8` | 336 | false | 2 | 0 | 1 | 17 | — |
| `00011c08` | `FUN_00011c08` | 208 | false | 4 | 0 | 1 | 14 | — |
| `00011ce4` | `FUN_00011ce4` | 208 | false | 5 | 0 | 3 | 19 | — |
| `00011db4` | `FUN_00011db4` | 267 | false | 2 | 0 | 3 | 2 | — |
| `00011ec0` | `FUN_00011ec0` | 283 | false | 3 | 2 | 2 | 15 | — |
| `00011fdc` | `FUN_00011fdc` | 103 | false | 0 | 0 | 2 | 6 | 2 |
| `00012044` | `FUN_00012044` | 76 | false | 1 | 0 | 5 | 0 | — |
| `00012090` | `FUN_00012090` | 3 | false | 0 | 0 | 1 | 0 | — |
| `000120a0` | `FUN_000120a0` | 66 | false | 0 | 0 | 24 | 0 | — |
| `000120f0` | `FUN_000120f0` | 95 | false | 0 | 0 | 5 | 0 | — |

#### Direct entry paths, indirect calls, and referenced globals

3 functions have a direct-call path from the entry. Each recovered path is listed; these paths exclude computed calls.

| Function | Entry | Depth | Direct path |
|---|---:|---:|---|
| `entry` | `00000354` | 0 | `00000354` |
| `FUN_0000041c` | `0000041c` | 1 | `00000354 → 0000041c` |
| `FUN_00011fdc` | `00011fdc` | 2 | `00000354 → 0000041c → 00011fdc` |

Ghidra recorded 186 computed or unresolved call sites. All sites are summarized here with their instruction, bounded resolved targets, and nearby data references:

| Caller | Site | Instruction | Resolved targets | Nearby data refs |
|---|---:|---|---|---|
| `FUN_000002a0` (`000002a0`) | `00000304` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_000002a0` (`000002a0`) | `0000032e` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `entry` (`00000354`) | `00000378` | `CALL qword ptr [RAX + 0x98]` | none | none |
| `entry` (`00000354`) | `000003d6` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `entry` (`00000354`) | `0000040f` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_0000041c` (`0000041c`) | `00000454` | `CALL qword ptr [R9 + 0x140]` | none | none |
| `FUN_0000041c` (`0000041c`) | `00000472` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_0000041c` (`0000041c`) | `0000048f` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_0000041c` (`0000041c`) | `000004ac` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_0000041c` (`0000041c`) | `000004c9` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_000005f4` (`000005f4`) | `000006be` | `CALL qword ptr [RAX + 0x118]` | none | none |
| `FUN_000005f4` (`000005f4`) | `000006e8` | `CALL qword ptr [RAX + 0x30]` | none | none |
| `FUN_000005f4` (`000005f4`) | `0000073d` | `CALL qword ptr [RAX + 0x70]` | none | none |
| `FUN_000005f4` (`000005f4`) | `00000821` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_00000854` (`00000854`) | `000008a6` | `CALL qword ptr [RAX + 0x118]` | none | none |
| `FUN_00000854` (`00000854`) | `000008ff` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_00000854` (`00000854`) | `00000981` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_00000854` (`00000854`) | `00000a8c` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_00000854` (`00000854`) | `00000ef9` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_00000854` (`00000854`) | `00000f7d` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_00000854` (`00000854`) | `00000fe2` | `CALL qword ptr [RAX + 0x50]` | none | none |
| `FUN_00000854` (`00000854`) | `00001012` | `CALL qword ptr [RAX + 0xa8]` | none | none |
| `FUN_00000854` (`00000854`) | `0000104a` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00000854` (`00000854`) | `00001064` | `CALL qword ptr [RAX]` | none | none |
| `FUN_00001084` (`00001084`) | `00001130` | `CALL qword ptr [RAX + 0x50]` | none | none |
| `FUN_00001084` (`00001084`) | `0000114b` | `CALL qword ptr [RAX + 0x60]` | none | none |
| `FUN_00001084` (`00001084`) | `00001161` | `CALL qword ptr [RAX + 0x70]` | none | none |
| `FUN_00001084` (`00001084`) | `00001211` | `CALL qword ptr [RAX + 0x70]` | none | none |
| `FUN_00001258` (`00001258`) | `0000128d` | `CALL qword ptr [RAX + 0x78]` | none | none |
| `FUN_00001258` (`00001258`) | `000012a9` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_00001258` (`00001258`) | `000012e4` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_00001258` (`00001258`) | `00001319` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_00001258` (`00001258`) | `00001334` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00001258` (`00001258`) | `00001350` | `CALL qword ptr [RAX + 0x8]` | none | none |
| `FUN_00001258` (`00001258`) | `00001373` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_00001258` (`00001258`) | `00001396` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00001258` (`00001258`) | `000013a3` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_000013bc` (`000013bc`) | `00001420` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_000013bc` (`000013bc`) | `00001457` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_000013bc` (`000013bc`) | `0000148e` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_000013bc` (`000013bc`) | `000014df` | `CALL qword ptr [RAX + 0x120]` | none | none |
| `FUN_000013bc` (`000013bc`) | `00001507` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_000013bc` (`000013bc`) | `0000154e` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_000013bc` (`000013bc`) | `0000156d` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_000013bc` (`000013bc`) | `000015b6` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_00001610` (`00001610`) | `00001757` | `CALL R12` | FUN_00011ce4@00011ce4 | none |
| `FUN_00001610` (`00001610`) | `00001764` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00001610` (`00001610`) | `00001805` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00001610` (`00001610`) | `00001832` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_00001610` (`00001610`) | `00001892` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_00001610` (`00001610`) | `000018e2` | `CALL qword ptr [RAX + 0x118]` | none | none |
| `FUN_00001610` (`00001610`) | `00001933` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_000019b4` (`000019b4`) | `000019de` | `CALL qword ptr [RAX + 0x150]` | none | none |
| `FUN_00001a14` (`00001a14`) | `00001aae` | `CALL qword ptr [RAX + 0x148]` | none | none |
| `FUN_00001b80` (`00001b80`) | `00001be3` | `CALL qword ptr [RAX + 0x58]` | none | none |
| `FUN_00001b80` (`00001b80`) | `00001c25` | `CALL qword ptr [R11 + 0x48]` | none | none |
| `FUN_00001cb8` (`00001cb8`) | `00001dbd` | `CALL qword ptr [R10 + 0x30]` | none | none |
| `FUN_00001cb8` (`00001cb8`) | `00001f0f` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00001cb8` (`00001cb8`) | `00001f39` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `00001fec` | `CALL qword ptr [RAX + 0x118]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `00002038` | `CALL qword ptr [RAX + 0x78]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `00002061` | `CALL qword ptr [RAX + 0x78]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `0000209e` | `CALL qword ptr [RAX + 0x80]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `000020e4` | `CALL qword ptr [RAX + 0x70]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `000023c9` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00001fb0` (`00001fb0`) | `000023fb` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00002a68` (`00002a68`) | `00002a8c` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00002aa0` (`00002aa0`) | `00002ad0` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00002aa0` (`00002aa0`) | `00002b18` | `CALL qword ptr [RAX]` | none | none |
| `FUN_00002bd0` (`00002bd0`) | `00002cbd` | `CALL qword ptr [RAX + 0x140]` | none | none |
| `FUN_00002bd0` (`00002bd0`) | `00002d2c` | `CALL qword ptr [RAX]` | none | none |
| `FUN_00002bd0` (`00002bd0`) | `00002d87` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00002bd0` (`00002bd0`) | `00002dca` | `CALL qword ptr [RAX + 0x8]` | none | none |
| `FUN_000035a8` (`000035a8`) | `00003661` | `CALL qword ptr [R10 + 0x18]` | none | none |
| `FUN_000035a8` (`000035a8`) | `00003674` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00003bfc` (`00003bfc`) | `00003e91` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00003bfc` (`00003bfc`) | `00003f13` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_000055d4` (`000055d4`) | `00005732` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_000055d4` (`000055d4`) | `00005752` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_000055d4` (`000055d4`) | `00005786` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_000055d4` (`000055d4`) | `000057a2` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00005c04` (`00005c04`) | `00005c77` | `CALL qword ptr [RAX + 0x118]` | none | none |
| `FUN_000084d0` (`000084d0`) | `0000850d` | `CALL qword ptr [RAX + 0x70]` | none | none |
| `FUN_000084d0` (`000084d0`) | `00008576` | `CALL qword ptr [RAX]` | none | none |
| `FUN_000084d0` (`000084d0`) | `000085b6` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008638` (`00008638`) | `00008691` | `CALL qword ptr [R10]` | none | none |
| `FUN_00008638` (`00008638`) | `000086c1` | `CALL qword ptr [RAX + 0x8]` | none | none |
| `FUN_00008638` (`00008638`) | `00008756` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008638` (`00008638`) | `00008779` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008638` (`00008638`) | `0000879c` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008638` (`00008638`) | `000087d5` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008638` (`00008638`) | `000087e7` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008800` (`00008800`) | `0000887c` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_00008800` (`00008800`) | `000088a0` | `CALL qword ptr [R9 + 0x160]` | none | none |
| `FUN_00008800` (`00008800`) | `000088bc` | `CALL qword ptr [R9 + 0x160]` | none | none |
| `FUN_00008800` (`00008800`) | `0000890a` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008800` (`00008800`) | `00008917` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008934` (`00008934`) | `000089e0` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008934` (`00008934`) | `00008a0c` | `CALL qword ptr [RAX + 0x8]` | none | none |
| `FUN_00008934` (`00008934`) | `00008a27` | `CALL qword ptr [RAX]` | none | none |
| `FUN_00008934` (`00008934`) | `00008a59` | `CALL qword ptr [RAX + 0x8]` | none | none |
| `FUN_00008a84` (`00008a84`) | `00008aab` | `CALL qword ptr [RDI + 0x70]` | none | none |
| `FUN_00008a84` (`00008a84`) | `00008ad6` | `CALL qword ptr [RDI + 0x30]` | none | none |
| `FUN_00008a84` (`00008a84`) | `00008b42` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008a84` (`00008a84`) | `00008b65` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008a84` (`00008a84`) | `00008bf1` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008c94` (`00008c94`) | `00008d9b` | `CALL qword ptr [RAX + 0x160]` | none | none |
| `FUN_00008e5c` (`00008e5c`) | `00008ef5` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00008e5c` (`00008e5c`) | `00008f3b` | `CALL qword ptr [RAX + 0x58]` | none | none |
| `FUN_00008f50` (`00008f50`) | `00008f7e` | `CALL qword ptr [R10 + 0x18]` | none | none |
| `FUN_00008f88` (`00008f88`) | `00009001` | `CALL qword ptr [R11 + 0x68]` | none | none |
| `FUN_00008f88` (`00008f88`) | `00009032` | `CALL qword ptr [R11 + 0x10]` | none | none |
| `FUN_00008f88` (`00008f88`) | `00009076` | `CALL qword ptr [R11 + 0x68]` | none | none |
| `FUN_00008f88` (`00008f88`) | `000090aa` | `CALL qword ptr [R11 + 0x10]` | none | none |
| `FUN_00008f88` (`00008f88`) | `000090e4` | `CALL qword ptr [R10 + 0x10]` | none | none |
| `FUN_000090fc` (`000090fc`) | `00009190` | `CALL qword ptr [R11 + 0x10]` | none | none |
| `FUN_000090fc` (`000090fc`) | `00009205` | `CALL qword ptr [R11 + 0x10]` | none | none |
| `FUN_000090fc` (`000090fc`) | `00009255` | `CALL qword ptr [RAX + 0x10]` | none | none |
| `FUN_00009348` (`00009348`) | `00009405` | `CALL qword ptr [R10 + 0x40]` | none | none |
| `FUN_00009550` (`00009550`) | `00009607` | `CALL qword ptr [R10 + 0x10]` | none | none |
| `FUN_00009550` (`00009550`) | `00009694` | `CALL qword ptr [R10 + 0x18]` | none | none |
| `FUN_000096a0` (`000096a0`) | `00009721` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_00009980` (`00009980`) | `00009ad2` | `CALL qword ptr [RAX + 0x18]` | none | none |
| `FUN_00009980` (`00009980`) | `00009db6` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `00009f87` | `CALL qword ptr [RAX + 0x50]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a01d` | `CALL qword ptr [RAX + 0x20]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a06b` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a229` | `CALL qword ptr [RAX + 0x68]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a41e` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a4cd` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a54e` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a565` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a577` | `CALL qword ptr [RAX + 0x20]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a6af` | `CALL qword ptr [RAX + 0x50]` | none | none |
| `FUN_00009980` (`00009980`) | `0000a6ed` | `CALL qword ptr [RDX + 0x20]` | none | none |
| `FUN_0000a6f8` (`0000a6f8`) | `0000a86e` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_0000a6f8` (`0000a6f8`) | `0000a890` | `CALL qword ptr [RAX + 0x168]` | none | none |
| `FUN_0000a6f8` (`0000a6f8`) | `0000a8b0` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_0000a6f8` (`0000a6f8`) | `0000a8d6` | `CALL qword ptr [RAX + 0x168]` | none | none |
| `FUN_0000a96c` (`0000a96c`) | `0000a996` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000a96c` (`0000a96c`) | `0000a9ba` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000a96c` (`0000a96c`) | `0000a9d1` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000aa98` (`0000aa98`) | `0000ac11` | `CALL qword ptr [RDX + 0x48]` | none | none |
| `FUN_0000b4d4` (`0000b4d4`) | `0000b586` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000b4d4` (`0000b4d4`) | `0000b5d8` | `CALL qword ptr [R8 + 0x68]` | none | none |
| `FUN_0000b4d4` (`0000b4d4`) | `0000b5eb` | `CALL qword ptr [R8 + 0x50]` | none | none |
| `FUN_0000b60c` (`0000b60c`) | `0000b6bb` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000b60c` (`0000b60c`) | `0000b70d` | `CALL qword ptr [R8 + 0x68]` | none | none |
| `FUN_0000b60c` (`0000b60c`) | `0000b720` | `CALL qword ptr [R8 + 0x50]` | none | none |
| `FUN_0000b740` (`0000b740`) | `0000b773` | `CALL qword ptr [RAX + 0x30]` | none | none |
| `FUN_0000b784` (`0000b784`) | `0000b7b9` | `CALL qword ptr [RAX + 0x30]` | none | none |
| `FUN_0000b7cc` (`0000b7cc`) | `0000b801` | `CALL qword ptr [RAX + 0x30]` | none | none |
| `FUN_0000b814` (`0000b814`) | `0000b840` | `CALL qword ptr [R10 + 0x38]` | none | none |
| `FUN_0000b84c` (`0000b84c`) | `0000b87a` | `CALL qword ptr [R10 + 0x38]` | none | none |
| `FUN_0000b884` (`0000b884`) | `0000b8b2` | `CALL qword ptr [R10 + 0x38]` | none | none |
| `FUN_0000b8bc` (`0000b8bc`) | `0000b8f6` | `CALL qword ptr [RAX + 0x20]` | none | none |
| `FUN_0000b908` (`0000b908`) | `0000b943` | `CALL qword ptr [RAX + 0x20]` | none | none |
| `FUN_0000b958` (`0000b958`) | `0000b995` | `CALL qword ptr [RAX + 0x20]` | none | none |
| `FUN_0000b9a8` (`0000b9a8`) | `0000b9da` | `CALL qword ptr [R10 + 0x28]` | none | none |
| `FUN_0000b9e4` (`0000b9e4`) | `0000ba17` | `CALL qword ptr [R10 + 0x28]` | none | none |
| `FUN_0000ba20` (`0000ba20`) | `0000ba55` | `CALL qword ptr [R10 + 0x28]` | none | none |
| `FUN_0000d558` (`0000d558`) | `0000d6aa` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_0000d558` (`0000d558`) | `0000d74c` | `CALL qword ptr [R12 + RDX*0x2]` | none | none |
| `FUN_0000d7a4` (`0000d7a4`) | `0000dae6` | `CALL qword ptr [RDX + 0x48]` | none | none |
| `FUN_0000dc64` (`0000dc64`) | `0000dce2` | `CALL qword ptr [RDX + RSI*0x1]` | none | none |
| `caseD_0` (`0000dd14`) | `0000dd7f` | `CALL qword ptr [RDX + RAX*0x8 + 0x123b0]` | none | none |
| `caseD_0` (`0000dd14`) | `0000dda0` | `CALL qword ptr [RDX + RAX*0x8 + 0x12430]` | none | none |
| `caseD_6` (`0000de80`) | `0000dec3` | `CALL qword ptr [RDX + RAX*0x8 + 0x123f0]` | none | none |
| `caseD_6` (`0000de80`) | `0000dedd` | `CALL qword ptr [RDX + RAX*0x8 + 0x12470]` | none | none |
| `FUN_0000e0ac` (`0000e0ac`) | `0000e0c4` | `CALL qword ptr [RDI + RAX*0x8 + 0x12520]` | none | none |
| `FUN_0000e0ac` (`0000e0ac`) | `0000e0d5` | `CALL qword ptr [RDI + RAX*0x8 + 0x12580]` | none | none |
| `FUN_0000e0ec` (`0000e0ec`) | `0000e10a` | `CALL qword ptr [RDI + RAX*0x8 + 0x12520]` | none | none |
| `FUN_0000e0ec` (`0000e0ec`) | `0000e116` | `CALL qword ptr [RDI + RAX*0x8 + 0x12550]` | none | none |
| `FUN_0000e0ec` (`0000e0ec`) | `0000e124` | `CALL qword ptr [RDI + RAX*0x8 + 0x12580]` | none | none |
| `FUN_0000e1b0` (`0000e1b0`) | `0000e1cd` | `CALL qword ptr [RSI + RAX*0x8 + 0x12520]` | none | none |
| `FUN_0000e1b0` (`0000e1b0`) | `0000e1e9` | `CALL qword ptr [RSI + RAX*0x8 + 0x124b0]` | none | none |
| `FUN_0000e1b0` (`0000e1b0`) | `0000e1fa` | `CALL qword ptr [RSI + RAX*0x8 + 0x12580]` | none | none |
| `FUN_0000e844` (`0000e844`) | `0000e85c` | `CALL qword ptr [RDI + RAX*0x8 + 0x12520]` | none | none |
| `FUN_0000e8a4` (`0000e8a4`) | `0000e8d8` | `CALL qword ptr [RSI + RAX*0x8 + 0x12520]` | none | none |
| `FUN_0000e9b0` (`0000e9b0`) | `0000e9c8` | `CALL qword ptr [RDI + RAX*0x8 + 0x12580]` | none | none |
| `FUN_0000ea18` (`0000ea18`) | `0000ea62` | `CALL qword ptr [RDX + RAX*0x8]` | none | none |
| `FUN_0000fff0` (`0000fff0`) | `00010005` | `CALL qword ptr [RAX + 0x40]` | none | none |
| `FUN_0001009c` (`0001009c`) | `000100fc` | `CALL qword ptr [RAX + 0x48]` | none | none |
| `FUN_00010264` (`00010264`) | `0001032a` | `CALL qword ptr [RDX + 0x48]` | none | none |
| `FUN_00011ec0` (`00011ec0`) | `00011fa5` | `CALL qword ptr [RAX]` | none | none |
| `FUN_00011ec0` (`00011ec0`) | `00011fc2` | `CALL qword ptr [RAX + 0x48]` | none | none |

There are 41 static data references mapped to program memory in the direct-call-reachable functions. Stack and other unmapped references remain in the per-function data-reference inventory. These globals remain addresses, symbols, or sections only; they are not assigned hardware semantics:

| Function | Entry | Target | Reference type | Symbol | Memory block |
|---|---:|---:|---|---|---|
| `entry` | `00000354` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `entry` | `00000354` | `000123a0` | `DATA` | DAT_000123a0 | `.data` |
| `entry` | `00000354` | `00012380` | `DATA` | DAT_00012380 | `.data` |
| `entry` | `00000354` | `00012d00` | `DATA` | PTR_FUN_00012d00 | `.data` |
| `entry` | `00000354` | `00012b78` | `DATA` | PTR_FUN_00012b78 | `.data` |
| `entry` | `00000354` | `00012370` | `DATA` | DAT_00012370 | `.data` |
| `entry` | `00000354` | `00012b78` | `DATA` | PTR_FUN_00012b78 | `.data` |
| `entry` | `00000354` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `entry` | `00000354` | `00012d28` | `DATA` | DAT_00012d28 | `.data` |
| `entry` | `00000354` | `00012d20` | `WRITE` | DAT_00012d20 | `.data` |
| `entry` | `00000354` | `00012d28` | `WRITE` | DAT_00012d28 | `.data` |
| `entry` | `00000354` | `00012b90` | `DATA` | PTR_FUN_00012b90 | `.data` |
| `entry` | `00000354` | `00012b90` | `DATA` | PTR_FUN_00012b90 | `.data` |
| `entry` | `00000354` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `entry` | `00000354` | `00012390` | `DATA` | DAT_00012390 | `.data` |
| `entry` | `00000354` | `00012d30` | `DATA` | DAT_00012d30 | `.data` |
| `entry` | `00000354` | `00012270` | `DATA` | DAT_00012270 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e48` | `WRITE` | DAT_00014e48 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e50` | `WRITE` | DAT_00014e50 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e70` | `DATA` | DAT_00014e70 | `.data` |
| `FUN_0000041c` | `0000041c` | `00012330` | `DATA` | DAT_00012330 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e58` | `WRITE` | DAT_00014e58 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e60` | `WRITE` | DAT_00014e60 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e80` | `DATA` | DAT_00014e80 | `.data` |
| `FUN_0000041c` | `0000041c` | `00012350` | `DATA` | DAT_00012350 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e88` | `DATA` | DAT_00014e88 | `.data` |
| `FUN_0000041c` | `0000041c` | `00012360` | `DATA` | DAT_00012360 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e68` | `DATA` | DAT_00014e68 | `.data` |
| `FUN_0000041c` | `0000041c` | `00012320` | `DATA` | DAT_00012320 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e58` | `READ` | DAT_00014e58 | `.data` |
| `FUN_0000041c` | `0000041c` | `00014e78` | `DATA` | DAT_00014e78 | `.data` |
| `FUN_0000041c` | `0000041c` | `00012340` | `DATA` | DAT_00012340 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00014e98` | `READ` | DAT_00014e98 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00014e50` | `READ` | DAT_00014e50 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00014e98` | `WRITE` | DAT_00014e98 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00012268` | `READ` | DAT_00012268 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00012260` | `READ` | DAT_00012260 | `.data` |
| `FUN_00011fdc` | `00011fdc` | `00014e98` | `WRITE` | DAT_00014e98 | `.data` |

All direct edges, xrefs and call-site records are retained in JSON. The entry decompilation shows indirect calls through a global function-pointer table, including offsets `+0x98` and `+0x148`; stripped names and unresolved pointers prevent assigning those calls to fan, clock, power, memory, CU, or board control.
The non-executable sections contain 45 printable-string leads. They are heuristic extraction results, not interpreted behavior; the visible examples are generic UEFI status text and do not disclose a supported fan, clock, power, memory-timing, or CU control path.

### Legacy x86 static code inventory

Each code-type-0 image was analyzed as a bounded raw binary with Ghidra's `x86:LE:16:Real Mode` language. The PCI option-ROM entry at offset `0x3` contains `E9 FA 5F` (`JMP rel16`), whose target is `0x6000`; the Ghidra root address matches that calculation. The 244 recovered function records, body ranges, direct edges, all 144 root-reachable direct paths, entry disassembly and decompilation are retained in the versioned sidecars. The entry decompilation remains at Ghidra's synthetic symbol level; no hardware or runtime semantics are assigned.

| Payload | Input image SHA-256 | Ghidra functions | Direct call sites | Root direct-call paths | Candidate body bytes / ranges | Indirect calls | Software interrupts | Sidecar |
|---|---|---:|---:|---:|---:|---:|---:|---|
| AS04 | `58e1d62292e887f1757bf037952a1eb2c2afae3df2f69bb0a1eb2c26c01f0b4b` | 244 | 674 | 144 | 10,242 / 60 | 2 | 1 | [Ghidra JSON](analysis/AS04-legacy-ghidra.json) |
| AS07 | `25bff40791168ac164be36d4d16f09d7654b123b95e5ac74c6990b8c41c38a78` | 244 | 674 | 144 | 10,242 / 60 | 2 | 1 | [Ghidra JSON](analysis/AS07-legacy-ghidra.json) |

AS04 and AS07 produced identical function entries, function-body ranges, direct-call edges, root paths, indirect calls and software-interrupt findings. The union of recovered function-body extents is **60 static code-candidate ranges** (10,242 bytes): `0x3–0x6`, `0x6000–0x60f8`, `0x610e–0x612e`, `0x6176–0x6300`, `0x6354–0x6385`, `0x6386–0x63ed`, `0x644d–0x6685`, `0x669d–0x67e0`, `0x67f0–0x6a97`, `0x6aaa–0x6c05`, `0x6c15–0x6c25`, `0x6c35–0x6c4f`, `0x6c80–0x6caa`, `0x6cb5–0x6d02`, `0x6d05–0x6ecf`, `0x6ed3–0x6f86`, `0x6f88–0x7020`, `0x702d–0x7112`, `0x7113–0x7267`, `0x7268–0x73f0`, `0x7468–0x753d`, `0x7546–0x75a7`, `0x75aa–0x7bb3`, `0x7bc7–0x7bed`, `0x7c4b–0x7c9d`, `0x7cba–0x7d35`, `0x7d48–0x7d6f`, `0x7d7b–0x7d9c`, `0x7da0–0x7e5b`, `0x7e65–0x7e68`, `0x7e6b–0x7e7d`, `0x7e80–0x7ec9`, `0x7ed6–0x7f98`, `0x7fb1–0x7ffc`, `0x7fff–0x8024`, `0x8055–0x8065`, `0x807a–0x8093`, `0x8094–0x80c0`, `0x815c–0x817e`, `0x8186–0x8193`, `0x81a0–0x8258`, `0x8263–0x82b1`, `0x82bb–0x8336`, `0x8362–0x83d0`, `0x83f2–0x840b`, `0x841b–0x8516`, `0x9473–0x96fb`, `0x9860–0x991d`, `0x9922–0x993a`, `0x99c0–0x9b2b`, `0x9b2c–0x9bf4`, `0x9c62–0x9cdd`, `0x9cde–0x9cf3`, `0x9cf4–0x9d51`, `0x9d87–0x9d95`, `0x9d96–0x9dcf`, `0x9dd0–0x9e2d`, `0xa2f9–0xa30a`, `0xa97c–0xa9c3`, `0xc80e–0xc81a`.

The other 48,638 bytes in each legacy image have no recovered function body. That complement may include tables, strings, padding, unrecognized code or disassembly gaps; it is explicitly not classified as non-executable.

| Site type | Caller | Address | Instruction | Static disposition |
|---|---|---:|---|---|
| Indirect call | `FUN_0000_9540` (`0000:9540`) | `0000:96d6` | `CALL word ptr [BX + 0xe26a]` | Static indirect-call site; target function is unresolved unless a bounded target is listed. |
| Indirect call | `FUN_0000_9df4` (`0000:9df4`) | `0000:9e17` | `CALL word ptr CS:[SI + 0x9e3e]` | Static indirect-call site; target function is unresolved unless a bounded target is listed. |
| Software interrupt | `FUN_0000_9df4` (`0000:9df4`) | `0000:9df9` | `INT 0x42` | Software interrupt instruction; vector behavior depends on the runtime environment and was not executed. |


The measured file ends at `0x1f0100` (2,031,872 bytes), while the ATOM FirmwareInfo field declares a 2 MiB SPI device size (`0x200000`), a difference of `0xff00` bytes. This capacity field does not establish payload coverage. The payload also contains unparsed bytes outside the option-ROM ranges, including a product string near the end and padding-like `0xff` runs. All such bytes remain accounted as opaque unless a supported structure identifies them.

## ATOM map and decoded fields

The common ATOM ROM header is format/content `2.3`; the master data table is `2.1` with 35 bounded pointers. In each duplicated legacy image the reporter records 19 ATOM structures: the ROM header, master table, and 17 non-null data-table pointers. The full table-by-table offsets, lengths and revisions are in the JSON record. The bounded reporter emitted no warnings.

#### All 35 public master-list data slots (first chain)

Slot names and pointer positions follow `atom_master_list_of_data_tables_v2_1` in the [pinned Linux AMD ATOM header](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h). Generic `sw_datatableN` names are source placeholders; their semantics are not inferred. Repeated-chain locations and hashes are compared explicitly:

| Index | Public field | Pointer field | Target | Length/revision | Classification | Repeat | SHA-256 | Body status or null-pointer note |
|---:|---|---:|---:|---|---|---|---|---|
| 0 | `utilitypipeline` | `0x40304` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 1 | `multimedia_info` | `0x40306` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 2 | `smc_dpm_info` | `0x40308` | `0x42420` | 532 / v6.0 | `identified_but_undecoded` | `0x122420`, identical | `be125c779843943029355edf444ef6ffb30eb213c670a42f57a77ae8d87e25cd` | The checked Linux ATOM header and AMDGPU parser source contain no smc_dpm_info v6.0 definition or parser. The 532-byte body remains undecoded; older SMC/DPM layouts are not applied. |
| 3 | `sw_datatable3` | `0x4030a` | `0x41cc8` | 368 / v2.1 | `identified_but_undecoded` | `0x121cc8`, identical | `b2879a7e0b16c15e3b5728ac885ade06858e80ab90e0fb691e280f1d077f61ba` | Linux's master-list v2.1 preserves this slot as sw_datatable3; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 4 | `firmwareinfo` | `0x4030c` | `0x42374` | 172 / v3.5 | `decoded` | `0x122374`, identical | `c77ae1917c2b7a3581f48b66108feba98567f809c290dc6eaaac1b08f3673161` | Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. |
| 5 | `sw_datatable5` | `0x4030e` | `0x41e38` | 52 / v2.1 | `identified_but_undecoded` | `0x121e38`, identical | `2f2b2f0fc009749c60c2812b6f0fc9c973e51b65550e65cc177163860a7c0b18` | Linux's master-list v2.1 preserves this slot as sw_datatable5; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 6 | `lcd_info` | `0x40310` | `0x41964` | 80 / v3.1 | `identified_but_undecoded` | `0x121964`, identical | `d13e27e3bd857735b5307f70c6e5bb79ba5389539ce7a52357ba3dee7c5e20ed` | The checked Linux headers expose older LCD_INFO layouts but no exact revision 3.1 structure; the body remains identified by its master-list slot and common header only. |
| 7 | `sw_datatable7` | `0x40312` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 8 | `smu_info` | `0x40314` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 9 | `sw_datatable9` | `0x40316` | `0x41f28` | 852 / v3.3 | `identified_but_undecoded` | `0x121f28`, identical | `c4ba4502feb17b1319c084fb25b5f3635d4cdf14604360e71368a2d765fa2e69` | Linux's master-list v2.1 preserves this slot as sw_datatable9; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 10 | `sw_datatable10` | `0x40318` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 11 | `vram_usagebyfirmware` | `0x4031a` | `0x4227c` | 48 / v2.2 | `decoded` | `0x12227c`, identical | `9dd46fe78637d3fb43d13e2eba7e8faa9d74c64640e492fb58c011b6614ea0b3` | Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. |
| 12 | `gpio_pin_lut` | `0x4031c` | `0x41a88` | 164 / v2.1 | `decoded` | `0x121a88`, identical | `2665e512e2e36de18518ffe532b03185adae750dc05a6ff4a54f01bbc90a07eb` | Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. |
| 13 | `sw_datatable13` | `0x4031e` | `0x41e6c` | 164 / v1.1 | `identified_but_undecoded` | `0x121e6c`, identical | `d300ed22e6bd874fb93858bb2a19d88198f4319e7e0d57dc4d45bf029fb8affa` | Linux's master-list v2.1 preserves this slot as sw_datatable13; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 14 | `gfx_info` | `0x40320` | `0x42634` | 136 / v3.1 | `identified_but_undecoded` | `0x122634`, identical | `ae4c3ddcc101afb3d2e86b6eeb3a6dbbdba2579529e8d79c94832049049ddde4` | The checked Linux header defines GFX_INFO v3.0, not v3.1, and the driver union/parser handles v2.2, v2.4, v2.7, and v3.0. No v3.1 CU count or mask is inferred. |
| 15 | `powerplayinfo` | `0x40322` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 16 | `sw_datatable16` | `0x40324` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 17 | `sw_datatable17` | `0x40326` | `0x41f10` | 24 / v2.2 | `identified_but_undecoded` | `0x121f10`, identical | `a04d40da66764a0b2c2558ba0657fc8b1d1d0ba74d04e8e590f68c0bfc5cdd32` | Linux's master-list v2.1 preserves this slot as sw_datatable17; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 18 | `sw_datatable18` | `0x40328` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 19 | `sw_datatable19` | `0x4032a` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 20 | `sw_datatable20` | `0x4032c` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 21 | `sw_datatable21` | `0x4032e` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 22 | `displayobjectinfo` | `0x40330` | `0x422ac` | 200 / v1.5 | `partially_decoded` | `0x1222ac`, identical | `4d57403033b75af2f442e34356128d4b9618d5be679823a447782683baec2eba` | The exact v1.5 path-array header and four entries are decoded. The remaining 128 bytes are inside the declared table but have no exact matched nested-record definition in the checked source; they remain identified but undecoded. |
| 23 | `indirectioaccess` | `0x40332` | `0x41cc0` | 8 / v1.1 | `identified_but_undecoded` | `0x121cc0`, identical | `561a37ab356f46e1cba0d707129131dfcaa6ab673b9d56cca9d382003adeead3` | The public INDIRECT_IO_ACCESS definition contains a 256-byte sequence after its common header, while this record declares only 8 bytes. The length mismatch prevents applying that body layout. |
| 24 | `umc_info` | `0x40334` | `0x426bc` | 84 / v4.0 | `decoded` | `0x1226bc`, identical | `8cdee8f64946e19e894e679faac505b860cff5dff2517d2a45faab987f43a27a` | Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. |
| 25 | `sw_datatable25` | `0x40336` | `0x4034c` | 5656 / v1.2 | `identified_but_undecoded` | `0x12034c`, identical | `10178c6e6b3c5d33aa538d3f6515131321d38a6654083b6f69394c7e4431b721` | Linux's master-list v2.1 preserves this slot as sw_datatable25; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 26 | `sw_datatable26` | `0x40338` | `0x41b2c` | 204 / v3.1 | `identified_but_undecoded` | `0x121b2c`, identical | `4a34ce12b92bfb4a05ef0eb47034a04eda1c9865dd69ce07801dd9ce57944d25` | Linux's master-list v2.1 preserves this slot as sw_datatable26; no semantic table name or exact body structure is defined there. Revision-specific bytes remain unresolved. |
| 27 | `dce_info` | `0x4033a` | `0x419b4` | 212 / v4.5 | `decoded` | `0x1219b4`, identical | `b65d753efc91bce3a9f3a84bc27ef46afc93551236dff3b297f0225b4f7467f6` | Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. |
| 28 | `vram_info` | `0x4033c` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 29 | `sw_datatable29` | `0x4033e` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 30 | `integratedsysteminfo` | `0x40340` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 31 | `asic_profiling_info` | `0x40342` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 32 | `voltageobject_info` | `0x40344` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 33 | `sw_datatable33` | `0x40346` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |
| 34 | `sw_datatable34` | `0x40348` | null | — | `null pointer` | — | `—` | No table record is dereferenced because the master-list pointer is zero. |

The checked public AMD/Linux [ATOM firmware header](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h) defines the observed `FirmwareInfo` revision `3.5` and its 172-byte structure. Both copies are identical between AS04 and AS07. At file offsets `0x42374` and `0x122374`, the table reports:

| Field | Value in both payloads | Interpretation limit |
|---|---:|---|
| `firmware_capability` | `0x00024000` | Current public header names `dynamic_boot_cfg_enable` (`0x00020000`) and `ENABLE_2STAGE_BIST_TRAINING` (`0x00000400`); the latter is clear. Set bit `0x00004000` remains unnamed. The training capability concerns two-stage BIST training and its absence does not mean all memory training is disabled. |
| `pplib_pptable_id` | `0x00001296` | Header comment says a nonzero ID selects a driver-sourced PowerPlay table rather than one from this VBIOS. This points away from editing a classic in-ROM PowerPlay table; exact R9700 driver behavior still needs board/stack evidence. |
| PowerPlayInfo master pointer | null | No PowerPlayInfo data table is directly pointed to by the ATOM master list. This is not evidence that no tuning policy exists elsewhere. |
| `bootup_clk_reserved[2]` | `0, 0` | Reserved fields, not zero-valued clocks. |
| `bootup_voltage_reserved[2]` | `0, 0` | Reserved fields, not zero-valued voltages. |
| `maco_pwrlimit_mw`, `usb_pwrlimit_mw` | `0`, `0` | Mode-specific limits; not general board power limits. |
| `fw_protect_region_size_in_kb` | `524288` | Header describes framebuffer memory reservation/protection, not SPI write protection or ROM authentication. |
| `spi_rom_size` | `2097152` (2 MiB) | Declared SPI capacity, not proof that the 2,031,872-byte payload is a full-chip read. |

`smc_dpm_info` is present at `0x42420` / `0x122420`, length 532, revision `6.0`. The checked Linux header has no matching v6.0 body definition, so it remains opaque; v4.x offsets are not applied. `gfx_info` is revision `3.1`; the checked header defines v3.0 but not v3.1, so no CU count or mask is decoded. Exact public definitions now decode UMC v4.0, DCE v4.5, GPIO LUT v2.1, VRAM usage v2.2 and the path array in display-object v1.5. The PowerPlayInfo, SMUInfo and VRAMInfo master slots are null. A zero pointer or absent table is only an observation about this ROM structure, not proof that the driver, SMU, fuses or board circuitry lack that function.

## AS04 versus AS07

The files have equal size. The raw comparison found **3,575 changed bytes in 89 exact contiguous ranges**. All 38 discovered ATOM records compare byte-identically at the same image-relative offsets and revisions. PCIR boundaries and IDs are unchanged; both legacy checksums remain valid. The two ROM chains are byte-identical duplicates within each version.

The readable version identifier changes from `7551OG.23.8.0.68.AS04` to `7551OG.23.8.0.68.AS07` at `0x400a0` and `0x1200a0`; the timestamp strings at `0x40050`, `0x43220`, `0x37fa0` and their repeated-chain copies change from `03/17/26,22:38:29` to `05/07/26,23:10:43`. The ATOM version string, VBIOS part string, board string, and GOP revision string stay the same. EFI headers, size envelopes, compressed stream hashes and decompressed PE hashes are stable across all four EFI images. The bounded PE was statically analyzed; no code was run.

The changed ranges cluster in pre-ROM data, inter-chain opaque bytes, legacy/EFI metadata and trailing opaque bytes. Every exact interval is listed in the JSON with a classification: recognized text, option-ROM bytes outside a decoded field, or opaque bytes. The grouped extents below are only for readability; their listed intervals are exact.

The [ASUS support page](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G) says the package refines the fan curve for a quieter profile. That release note and changed opaque bytes make fan behavior a reasonable investigation hypothesis, but none of the revision-6.0 SMC/DPM or other changed data has been tied to a fan-table schema. No AS04/AS07 byte difference currently proves a fan curve change.

### Exact changed-range clusters

| Cluster extent | Exact changed intervals | Changed bytes | Disposition |
|---|---|---:|---|
| `0x14000–0x14100` | `0x14000–0x14098`, `0x1409a–0x140d1`, `0x140d2–0x14100` | 253 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x15000–0x15100` | `0x15000–0x15100` | 256 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x16000–0x16100` | `0x16000–0x16100` | 256 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x17000–0x17100` | `0x17000–0x17078`, `0x17079–0x17100` | 255 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x18000–0x18100` | `0x18000–0x18100` | 256 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x19000–0x19100` | `0x19000–0x19029`, `0x1902a–0x19100` | 255 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1a000–0x1a100` | `0x1a000–0x1a100` | 256 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x20f00–0x21000` | `0x20f00–0x20f0d`, `0x20f0e–0x20f64`, `0x20f65–0x20f6e`, `0x20f6f–0x21000` | 253 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x37f00–0x37fb1` | `0x37f00–0x37f10`, `0x37fa1–0x37fa2`, `0x37fa3–0x37fa4`, `0x37faa–0x37fab`, `0x37fac–0x37fae`, `0x37faf–0x37fb1` | 23 | `identified_text_bytes, opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x383e0–0x384e0` | `0x383e0–0x38433`, `0x38434–0x384ce`, `0x384cf–0x384e0` | 254 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x40021–0x401f1` | `0x40021–0x40022`, `0x40051–0x40052`, `0x40053–0x40054`, `0x4005a–0x4005b`, `0x4005c–0x4005e`, `0x4005f–0x40061`, `0x400b4–0x400b5`, `0x40164–0x40168`, `0x401ed–0x401f1` | 17 | `identified_text_bytes, option_rom_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x43221–0x43231` | `0x43221–0x43222`, `0x43223–0x43224`, `0x4322a–0x4322b`, `0x4322c–0x4322e`, `0x4322f–0x43231` | 7 | `identified_text_bytes`; unresolved intervals remain unresolved in the JSON record. |
| `0x4e659–0x4e65d` | `0x4e659–0x4e65d` | 4 | `option_rom_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0xf4200–0xf433b` | `0xf4200–0xf4210`, `0xf42d0–0xf4300`, `0xf433a–0xf433b` | 65 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0xf47b0–0xf47b8` | `0xf47b0–0xf47b4`, `0xf47b6–0xf47b8` | 6 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0xf5340–0xf534d` | `0xf5340–0xf5346`, `0xf534c–0xf534d` | 7 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0xf56d0–0xf56d4` | `0xf56d0–0xf56d1`, `0xf56d2–0xf56d4` | 3 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0xf59e0–0xf5ae0` | `0xf59e0–0xf5adc`, `0xf5add–0xf5ae0` | 255 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x100f00–0x101000` | `0x100f00–0x100f0d`, `0x100f0e–0x100f64`, `0x100f65–0x100f6e`, `0x100f6f–0x101000` | 253 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x117f00–0x117fb1` | `0x117f00–0x117f10`, `0x117fa1–0x117fa2`, `0x117fa3–0x117fa4`, `0x117faa–0x117fab`, `0x117fac–0x117fae`, `0x117faf–0x117fb1` | 23 | `identified_text_bytes, opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1183e0–0x1184e0` | `0x1183e0–0x118433`, `0x118434–0x1184ce`, `0x1184cf–0x1184e0` | 254 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x120021–0x1201f1` | `0x120021–0x120022`, `0x120051–0x120052`, `0x120053–0x120054`, `0x12005a–0x12005b`, `0x12005c–0x12005e`, `0x12005f–0x120061`, `0x1200b4–0x1200b5`, `0x120164–0x120168`, `0x1201ed–0x1201f1` | 17 | `identified_text_bytes, option_rom_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x123221–0x123231` | `0x123221–0x123222`, `0x123223–0x123224`, `0x12322a–0x12322b`, `0x12322c–0x12322e`, `0x12322f–0x123231` | 7 | `identified_text_bytes`; unresolved intervals remain unresolved in the JSON record. |
| `0x12e659–0x12e65d` | `0x12e659–0x12e65d` | 4 | `option_rom_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1d4200–0x1d433b` | `0x1d4200–0x1d4210`, `0x1d42d0–0x1d4300`, `0x1d433a–0x1d433b` | 65 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1d47b0–0x1d47b8` | `0x1d47b0–0x1d47b4`, `0x1d47b6–0x1d47b8` | 6 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1d5340–0x1d534d` | `0x1d5340–0x1d5346`, `0x1d534c–0x1d534d` | 7 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1d56d0–0x1d56d4` | `0x1d56d0–0x1d56d1`, `0x1d56d2–0x1d56d4` | 3 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |
| `0x1d59e0–0x1d5ae0` | `0x1d59e0–0x1d5adc`, `0x1d5add–0x1d5ae0` | 255 | `opaque_bytes_unresolved`; unresolved intervals remain unresolved in the JSON record. |

#### Exact changed intervals and raw evidence

Every contiguous changed interval is listed with its classification, before/after SHA-256, and complete hex bytes for ranges up to 256 bytes. Longer ranges retain a 64-byte prefix and full hash in JSON.

| Exact range | Bytes | Classification | AS04 raw hex / prefix | AS07 raw hex / prefix | AS04 SHA-256 | AS07 SHA-256 |
|---|---:|---|---|---|---|---|
| `0x14000–0x14098` | 152 | `opaque_bytes_unresolved` | `695d05c4965b71fd7be053a4936d0a1f187ec1834f2674567f45534de561a3b8571d6ce9c9580b5ca2ed4723f7405e8532faf9fe2788d85b56c71e8b5b4f023f9640a663b9934a6d2023903a8e2aacd8b541594db171ba50008c19e737d7fff2de4f0e5caf398e5fa1310803ffd345966d7dce96837c2e6e114018798ff031f6b46b6af034aa55cf34465a66e04862e1a9a9b1c1ddc1ad8d` | `93479d7162073a1f9bb908f284123d644ad17b16d930cda14b3dc53be205ce36ebcd9c6350852613c1d9ebae1942c7799f970e9771fd3a1679cbd04e4465a46cf3961a81e923609dd43b3d50e99c11a6c3a5ebc4b740bd7cf0044aa8798aba5a7a15ddb177593cd540827f5845f1cf26cff99572f54585e35c500e3ddc3221f3a1db3f61043e790e3f0509462e50a1b2b82b3810d1582b30` | `bd97fd39a9d801afbfa93a3746d4da095f06a2c46230e43a75c3e73516bd64b8` | `dcfe5e71a9d4960447b2df66535950ff1cbde7a682983d386b570cc1eff5b63c` |
| `0x1409a–0x140d1` | 55 | `opaque_bytes_unresolved` | `2e84d12517c5ca9f76e966b7cd6ab7ebcc910b72ee5febc987e964cc1bed46f0969f152b4aba93b2e5e8f57a09457b09cb480ee04ab691` | `f7175c39e2226f56010f609e9253ce24a9c49a816f573affb4822b32491bd5266afeea2ca54ec0c7c72ed4abac7e45b0c992ba389ae979` | `8cb7ccc646a0dd2ce12a687f665280655c8b23c9ec8bd65614925d41b2787a31` | `920764085d9bf590cc017710e4371081857e71246039cba728ddc151a30f94ad` |
| `0x140d2–0x14100` | 46 | `opaque_bytes_unresolved` | `1c71dc58e617bccbbe7be912a2a857a2e408708e3c0501a14aa89fa7022d15576631aa26600c08c1bd52408ed051` | `4605b58e44a9d990737aff16c07bba4531641b9dff3d82a610bb350bf88b3e907327a2324ffd86d2dbd2d7c7b2cb` | `459cf5f849eb43c7bafb8b665f7ea18046bc77edf8431db7a2ae7d01f2f8408b` | `eded57f4e53fe1b15b595a34a71c77a2ff3dadbe96fb0b867c4952778462a7c1` |
| `0x15000–0x15100` | 256 | `opaque_bytes_unresolved` | `a269efa082a53304bbd4c11fde50321910c8f9399da8fe0274d161cf0f9d139f8f53936f05b4c914986614aaa9522af759a8319657f2c9c632afb916564fa34d2998feb63a9b30ce626c0812086fe8b7c515bb2fa6657467b82cdad02005327ea6c789a85065c7d4be45321c3840989f9740950d8bab5abe2cb6b6f2a020de73d2d9f4b6aa9cfdbda97138d9fe8d23a85cbd6edf72e3e2b8279b5a0928aec2e8c208f1b3d14059d510aee488a43c786b231b20344e2d7269aa3d8a33b3c227c0e5cab77f8eeed50d90680c0243bc0e417df2835a78f852082c4ec020de805f053932b3c873dd451277ad1529ec2de4303b8a74ab2c89440c9540cde4fce73cb4` | `64f8f1751b88f51743aef799ab21593aaa73d0280dee3a87548dd07590f17421e3469692220ece1c9c63f0c80779b8718b44f4940e3a7c4be197f9dfa3ff0374c7cde3ad3f5161be60edc21d5faa1ed122a9979ba3cdd4c58b474dbad2e0d7edb5c4689018a1c278fc52c410f1255408c284d7c0a0a6a3cb61a4aeef9b12585fe107006127675f5e8de11eb0d007912675dee31887400c2d641e0b4c60d4bbf8ecd46b5f926122aec739e68648b75636e669c45d1fbe909c796e4cbd91e984e52c3c2ae37a040083a80fa2f6d75255ebb3233d70f14daac90f1c0267ec6c018712722a787435f711ed6812187886fa230069b79299c9965a4b43baf02474a814` | `72804cfad69dda5277018d949e63c02190a39067be7778c1f3ed9dc8cb2d8516` | `069401d3c5af814dcefa309d8fb8566a5b6edacaa324b430a2a8a8bc5a728b25` |
| `0x16000–0x16100` | 256 | `opaque_bytes_unresolved` | `fe45032a1894111b39c0e7278270c1f39c450806364cd70e2cb5f786e8b656960f138edc468520e3ac700792b5ed01eaf8783830bfcda98381386f5441f1bf1ee21e261aa09ece56a23ed2d0a7ed8a4a26d4278f79eb2833d747caef235c2b254d29c22bb84708a5ab181f4a3ce4e84da07e8ce2a98d66c581d6c30bc79c630785d81a0c45a21101dde1356ab31c795cf7dde8db48a117cbab59d1f16784b701e454c25af3e53c6c4af75da0480ab13e99e35857d01cbeea5e88551e87ef4a4d8944c34dcdd832a8d1af961219230d2a2231b0ac4ecf20be3bef967a7c9875d1434d0bace1ce686569ac1e31e70c9212d8cca01263eb75d3e797a5f840e10574` | `d410c360781462d58404ae375c581315311b9faabd4f809e893eff676e4cdfe56d9e5f626fa8937105be92dbc29a3af03f493ccd7af0b012aae13cd8c89ddefcda1a2324bddc123576efd84f47f2cd51babe383a5460bb1b7cf6f74a7feee30f3014e88ce93ead976791a8064dd722d7bb2f17e8082eb36a5268c1821e4e15587311dc20497a5c335d6a5259a668033bc7c5bd7d962598addd121926bd98fe8de6460074355b9aa422ebe2f57f8d845535e2f1e68595d0ac3f4b59964dd78dd6864c35cd09850180cf81a72b8953005de841ebd14f11c5de7ad0faf19317d99f7a955d72cc7350dc47493149a117de9aee3d976dcf9fb7567ee0d3a1431f41c9` | `b7167310ee374f3ad18239873614aad4e00b656f3761cdbc09482ca5d9927d2b` | `4d5ceda7fd1e0753ad9094794b68ecfe93c37ff6f1de5e2f7e819af77f206a6f` |
| `0x17000–0x17078` | 120 | `opaque_bytes_unresolved` | `46bf06132eb53272564448e009bbe03cf7ec8a90ed1cbf3720815ced16d4f82e0636e47dbdca7d0b29191fe88405d42f55099409c79de1bdbb6e78c7ad0129eadc5da1afe701c70199a7e7cb93781c2c492f30e0d9810e776d4e0211cec92e88cbf794d736a265040e356b4dc90166f1dfab821f92387d07` | `968df0ec32068976fffe166c7a3a722d73014def14e65397dbf78eb30db12766ae180342ef00e6a0f296034c64a4be3bb10f0063f3fb1c5e8781b9c2a1483a351227ff48ff158017ee746c17f70837852cf75a6f0fb1b808ded952eac9806bfb7440e6558465db1bdfe3b20d46d3d7ec8ea8ae7e5f27670f` | `7eb0c6c2c9d0a9bc32685b4eae0359d4348a3db53259fc6adafc3bcdab0ab1f8` | `7b4a30ae3b59dfb2959c1ae2f9f6cee4df0d64dabc51615b3cbf7c528523b5e1` |
| `0x17079–0x17100` | 135 | `opaque_bytes_unresolved` | `441cef3029d074900a5fcdd718930e0b4287b48d8a921dd7549a8485d44f667a7d040b86b234a0d8bb5017bbd4394fa4d0c7df7db8a03b9c0f1f7a43e9a879166257b746f5e8399cdd9279fc464935093eec722b4404701fbe5cffb6981ca3a7c97e791f87fde84a065be9fd916f0536ac7d522b5e09dfb9b8b9520b1303031f0de5c53136c89a` | `ad0f78ab12f4a90da43ef0b1fdbfa16faa422ed47df63e32dce9776b1f13ba342dbc82ef87325840b15f446bb79a7e959393141528854c69f3d6e8423cb34aa2798bd350e7686abcf3b70dcb8c0146f5c4d782eb22fabcea8842c0837c309e8a135cd8d7762c08bb07f11fe04f61a3f6cc7aad6d6edcf4d218c487057c51d66b48eeeec7067d4d` | `a0f0ad7bf7f29ce8fb6f9cd8fcadd0fc8647a40b4b883cbc82b7cf3d2636b1c7` | `5c7bc08883de08b16e59e680daea5b1566250a75f8758d9ba8a4218c489dbede` |
| `0x18000–0x18100` | 256 | `opaque_bytes_unresolved` | `5802bd40e36fec88f54f9b61e2bd1ae76b07465ad4e9d3ef46c619f1fc923b76ff6f1ca11d6bfce663a5cd41a17247c5b34c3ff6a4f558e1acef3f22dfd459a25da693d911447209feb664b26ada885f9f8f3b588ed296801e752c5fbfe4cebfc735887d3e8342b910bc87ba74d2524e7f197327b610b375f0f6a170d0bac2bc338fda63b2538cc6b105f8780240ab1655a0302cbd61c91a58a4d1fdf914174b94470d8d65f3603445ce3829df07bdc234052f667071db9d32fdd1c64c1176196c26683083260469bc8a201f57e9cf5f809a7b9f6be0d41ae4a93409fd71886f3b9735cc10621b20825dc2209b2b87d79df406c10f83a809c77c95c91f8a4365` | `27bf1cb3c8f51169ea46b0256b4e85fd5093f69e8afc9216cf15308d70506115b08bb7d1d613625609b1737ec244a9733e0e049ccc550eb8cb480977684fa3985f0f79f05572966f05558e4b0ee3364e1f86061dea6060ee8539661797ed85f7e5be1ab5c41be153812aa019a9fe611019d1bb78914d9aabb685d4c2759e788d89dbf677cb8c0897c9dbe26bbe1175bda94f4736a20f2917bcbcc80d59ae1e83d124942f6e04ab0f848766b7b08568410533e07f751dc51305764907c34a467e0f3b881cf47b43a8e8bd0ac074064878f442e8e32dbdd5d2e32ceae0510a879c65b4586ff6cdfe214d77f7f8ccd999098e695b59971baf6955defb51a408dd96` | `9feb3aa6ec2f273a624b5d8dfb8ec43e60f4f0b3361f2e4028e43370ffe83094` | `e2f55a31a0bac3f77498adb53918feb60735fd9ba092e8b73928a5d2b239fa4f` |
| `0x19000–0x19029` | 41 | `opaque_bytes_unresolved` | `edc75cf9171bb9a304e72d06d42d0b99b514221c79e64fc0989baf10e069f031b9940cbf8b87966728` | `de5676f080bece914e425dd4801f93c308e7d07af6936dd338aaeb74ec4ffeaddabffb802f45eff441` | `130e36ef824f01fbabef80115208b3b9d70ce0fd3c4947adb316e5a4fff0f087` | `ce3700567bf4e1a164e44c8d09bc9f310ec15de43cba38f8291ea0dc8d9d5181` |
| `0x1902a–0x19100` | 214 | `opaque_bytes_unresolved` | `0d01e7b94b4f3625c3712ab47e4eea022d0e84e44d2e1181498a308411af0a789d9d2c9a5c195148d27d6b32cb46306a6fa38405d7b75263319fe18dc9f429217d3c81dd2b388ec3be81033e81a5c92c5533460d28284ad46cbfddd099ab40320a28a56904a93422b06cd61c1fd76161a1385a8b63cebe5a50409f84f3ac6a923a78060166775a916ea432798e44348bb07adf7cd78009b8d191fe0f2f7e1aaa7b56c95bb97ad57effa177bf57f990675710965cd3a5281633f637353dada3c4b41fbbdb827ee78fcf586eec7575695a5fc0b0a0d34e` | `375725530ce7bce878adcb9c998ef63ff5cabbfa4a77689c87efb2f38a13ae968ad926f78a5339375e3e9cff567c0d8700aca20f763f1040f88f832bfafd769ef239d38a1d0b6d3dca6f50301e5888adee3f3effc3d138f89eef7934a3ca8fa177e5b9379472357010f90e5948b61f7f4a20747ccd8c3e2e001cfd14d38bd71ed598243c8c0f8276a5a25d66030266e43f09cc7932f3a5d954af0a2e9ba7a02a4322020c15ffb5822e0d6cec62fd09bb0f80c4bd56339b6ccab445ce7ca4a5bf2feddc0e3e5625a27bffe720fcc256455676123dc33f` | `c786592df1324d0e42705f051a86c65a4f7a105ab1147d786aa31e9aa6d7e362` | `a9fe7052a95cfb278289581d21e4f98a3005969143b4a2a514f6a03aa88c8629` |
| `0x1a000–0x1a100` | 256 | `opaque_bytes_unresolved` | `165626be67e32bc4197109ab7fb8c46ac487554c15da2f3c344c9d542d156b9e1b688eedf9d49170f54600b33588efebe9f3342e6dbf6faeb6ba51c02af28bd56094270e41f5104076391eb0513453f1f386d6b58c2f1ea8592aba5658785864263b1112936043917da3078b907a966b35f8651ff0e127635a2cbce7190d4f71860b5217c99772b8e5262e0832fe315c79278caf361a2e7970c5e2bc1c1e64b7494073d831e3693e107d281f5eddbfa9b4e322e4841568ee174ffbb6f85fd503ae0272dd103f02dbceb8157703b1ce770d79d90e26b3ec52e6b266d10612472961c0110249e62d71ced656da7621103e0334330cb94b60a1ae77eb908a077674` | `18aff6cf87862d846362be7f7283e476515db4ebb8cfece55ff1e2e84c1cbf2365074dd4abdfe4c63e898af7ec66eb1c1e4afe41bfbba4fad92e2fe7e550872e90711e0554095ff9bd50907d2a91dfdb54e9372cfaa9000995fdf3156e5d6fa19fa8d18791f000de87e588018412557e4027e70a16dcfd8ad021fa16aab16f816b6bf7c46e51cefe929d8cb4604e27cf303da9809a3688bf2719bba1902fff1209de7e3e9f9ba54d64faa1b4233740b840e45b5ab45667553399231b39c3a79134d5d00d1f489a5e1ebc149a48430ad34b55a2e6c00a11ab598863150930b9bc6ff84539f48656ec88277349447d4227131c3ca769946b24bdc38dbc452acdcd` | `24d3015efc1f49f0508794346e76d11f3a08566ff1c27f6cd882c0658cc9c38d` | `078d849a2082d8b9c92ffe12ecd0de31764adca773a85980e8e277d559ed8ca5` |
| `0x20f00–0x20f0d` | 13 | `opaque_bytes_unresolved` | `d6fc756b0d4e392338887b8a91` | `9c3c50bdd44169f13ddd74de6c` | `4db9ff850540b2b3d1878d4d7fe1694df5e4a77e3f4734912b1f1b4882219f1b` | `d1677bef8e588f08d0c502ff34e2034e443b678f2bd4b6e2aaa48e120f450dc6` |
| `0x20f0e–0x20f64` | 86 | `opaque_bytes_unresolved` | `9d546f813561c4e11ca04aa461be80dec5900390fbe4af7a772998f7fd070b2e8757a24e04e206e61b231c94a8235357bc097bbe359b58e4e33c9f986198f88316d2eaebd0a3ff199b11b77626a6452ca7623f276efd` | `03ed0762947dad49e5b1c3f119ec4543652a6cf6623ddb33ce01f59324374c99ec4f79dfceaa34cf0eeb7af231bc3c469595f9fbd18fdb581777e09e6a4f42997f0ebeb8d261ad39b6c95a0d61f44011a43738818c6f` | `4683a0be3ccc555d50c6d757a544bee19a4cb313d592c95840ca6030be82a164` | `0a5042afbda23974fdca2a04fbf71c5b9bd98d805fd086ef610be26c11a8cbec` |
| `0x20f65–0x20f6e` | 9 | `opaque_bytes_unresolved` | `9564a1d2ec395bfab1` | `2631278d3cad5e734b` | `ec07d09426b6ebedcaee1fd15009ab0caf5a5c92f354d8dc019a00dd4f8794f4` | `f40bb755bd753c9b0ecd884437d76fcd9de36c87bc239fb26e0d3e335602f6e0` |
| `0x20f6f–0x21000` | 145 | `opaque_bytes_unresolved` | `b4b6e7c3fa0440e9442ae8b77c49431440360625480f0248bcc6320dea25c15ee1424ed824e61e3feea8133f84a7164511525f3c335ab3af0e978a1f8e1a84f6c70bcbc0a9eb512773992a5cab99ccea71a8a6d269600a01d8a256819012ed4411a2c60c9da53a70897a0872396b8192dc4ddfea84da270d0ff258989a20b5add0c6840bab90944610411c8935da6f50b4` | `03f82cab58f5bfc936da77ea87de55a6d818ccc6dd75910e6d68087967fade13cbf600fc88b5a17e0998d005f4dc66f8457c9958358d5b4212b714556e16e0fb76168f673b66fe7c247867a2b7d3738d0593725e37bde576fdd13840966ad71a5bf1285ad9ac14dd04062fe9c39ee5edd43a3308c0630b2d1a16bd1061c393696c41114fe151cc7656066fbcf2046dc174` | `23d7064a5849ae961ad4645db61c837fdced18265a1c4179338298b7de6273a6` | `ae72390b1f1a6cb01c27b6f6ccc02d893e877b6d1553976d21e8096604e0edae` |
| `0x37f00–0x37f10` | 16 | `opaque_bytes_unresolved` | `a6c4877292cf3753094bbc748b3638b7` | `f051f3270b78e5fcc7ecb593f4d25562` | `82fc9a130c2b99bed612baa5239ff06047bb4748d79b24566fffbcd0cc5a37a7` | `58e3904e4adc0fdee9fab4693273632b96133dd364c17d0a929055888e4e01e6` |
| `0x37fa1–0x37fa2` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x37fa3–0x37fa4` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x37faa–0x37fab` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x37fac–0x37fae` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x37faf–0x37fb1` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x383e0–0x38433` | 83 | `opaque_bytes_unresolved` | `0c2385c5767ca580d15e903633897dfb467492620c36a9ce30e7912ec038840e47f02b72fac432916f5ae7076444ffe66217150870d4883e240b391c6d854c789f549acbeff7ddfec80dc1536c50b6bf7adeb5` | `197f5d0d244d192a68c4f4278e6c4ad1d8de2a6eb3686fd323d5eac23e47ae41a6aaa0d0e48383d820dddcf46632bed117d29fada589ade8705764a14571f613fa527ff670fcbcf23ed76ea0ec731028581f93` | `d178fda029bd692e6d0dc01bebd3804fc19975a7763b5a658e9fe151f3182f43` | `75a84be8dc69731315ce5a6b5758b7dfdd681a4c4f0758dff04bda9aa383d182` |
| `0x38434–0x384ce` | 154 | `opaque_bytes_unresolved` | `f11b88c913fc798b79e88a15aa46deaf34e4fb96c619f7dd95a78f0fe385abddb7ee71a7594d74840c70284934fe999590789692d509166b4f84740741c4995e2444adb33b5adc01b3d9cc94bd9d5a22a59a7fc950b9b3e550dd97604d0e18541a3a7f8531c62def2cf18c70452ad6ff12bb9183ad9e71e7b841626842675f4dff90f5b302e9e3ff9a54822810277d7507864a2d77b325c92d38` | `c62d4927d622ebe19cb82ea9719b8cd5318de6703e6d69032774a956eb202f26f01116d3912036abea222b6db024cd2e944ca3608c615bc9d730cd22a55b7632d818683f13ef89996adb23c0548a993071864f6572fecd51807f6010aa5e9ec0e6435abfd31d8c16eaacebd37f184dfbcab1e4cc420c1f24d8f1227b2fde65ddfed87d7560efdceddac9b9d7e4dd90d7c677679abe688bc03c5b` | `ff413a0dffc947c046921084fd58ff5f55c1eb6b1298b4d56ce9adb90ce24c71` | `f87f18c048dd3d5649ff66ea513e36a417125466389600fe0ade1c0ac98743ab` |
| `0x384cf–0x384e0` | 17 | `opaque_bytes_unresolved` | `87704f628fb477f550771b72981c857755` | `a5d8f6c1757b4e51be981ad6c4d6206417` | `0a1cdcc29358f673d805ccd9c7e4364c62e3bdb74f5cffff7ed2d4ce572430c6` | `3a95eb9365e511ca46a6e6a8e8043c62fee44fbba97ec3461550fac90f3e74a6` |
| `0x40021–0x40022` | 1 | `option_rom_bytes_unresolved` | `73` | `6d` | `043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89` | `62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a` |
| `0x40051–0x40052` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x40053–0x40054` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x4005a–0x4005b` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x4005c–0x4005e` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x4005f–0x40061` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x400b4–0x400b5` | 1 | `identified_text_bytes` | `34` | `37` | `4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a` | `7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451` |
| `0x40164–0x40168` | 4 | `option_rom_bytes_unresolved` | `30383134` | `36313938` | `c75eca238ec250c28443dcb5bf69f9af1d465b62ebe19ef91874801b1b29bade` | `529f951b64739ac49f4bd732fb4aef675c34fda5acedb8cc01d030cd3301c22c` |
| `0x401ed–0x401f1` | 4 | `option_rom_bytes_unresolved` | `6687108d` | `740f0215` | `6160650dd4fc2a4f4d1dd231e515106dff071b2b5149624ce7db87fcbd628909` | `c79128147e5c5e4aed53e2ee749a13e20b6e3ba8c9124a0d19114a943abd8aa9` |
| `0x43221–0x43222` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x43223–0x43224` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x4322a–0x4322b` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x4322c–0x4322e` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x4322f–0x43231` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x4e659–0x4e65d` | 4 | `option_rom_bytes_unresolved` | `30383134` | `36313938` | `c75eca238ec250c28443dcb5bf69f9af1d465b62ebe19ef91874801b1b29bade` | `529f951b64739ac49f4bd732fb4aef675c34fda5acedb8cc01d030cd3301c22c` |
| `0xf4200–0xf4210` | 16 | `opaque_bytes_unresolved` | `584d34cb08f28e8696cd09c8200f6d8b` | `7c9ae8a1b03cf520ad6375ea22ef6c3e` | `98fc56e439aa18fe5d258cc15c4c593b4e9b5b75e73eb9bb2672cae22aedb4a0` | `1cb97408655d6a88161bd50c417329e1b36ccf933ed4008b974c89f3eeec58cc` |
| `0xf42d0–0xf4300` | 48 | `opaque_bytes_unresolved` | `207ca7c1fe25c4452f286fe016aac62598f0f47ab7fddfe482c75371345a450e9fd77b91bbdb317a848641965bc1ce8b` | `e33cf57e3640f4ca3a16cca2197850d7dd04a2b32e939c30844edef2118686246c2addac33043a29785a98a758b5f68d` | `ed6b2c902cc22bd1f6698ebc9c5b4ee16361ed1aaf5406f7dc6d2dbfac3b1ee3` | `cf7410931cb60303918001d54650ed313d29f9fdb745ebc39545c9244c503b11` |
| `0xf433a–0xf433b` | 1 | `opaque_bytes_unresolved` | `60` | `b9` | `8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3` | `04d6c0c946716aac894fc1653383543a91faab601302cf011607c82f06304651` |
| `0xf47b0–0xf47b4` | 4 | `opaque_bytes_unresolved` | `ac0dac0d` | `b80bb80b` | `40f11cfb8e01823607cd41ee77d743988f478cade1401431b441766279b6ef1e` | `f5203c6627b95d70b17d3542af629e6892c7afe58c42f7f83089a5ab4ca7b812` |
| `0xf47b6–0xf47b8` | 2 | `opaque_bytes_unresolved` | `ac0d` | `b80b` | `64092f06dca78a2dfb394a194e56b7222a5d4b3b746c2b6d0bb685e75b712afa` | `cd2b4698bb7d0c92d0d6f9bf41a591732ddc53473584af3792e72e88b714ad0b` |
| `0xf5340–0xf5346` | 6 | `opaque_bytes_unresolved` | `1e1e1e1e1e1e` | `0c0c0c0c0c0c` | `20f1a027e69979fe9fef5e8e3dd56f5e5a850bf4b96b880642eb80151a2659c5` | `7b2aa16484b6ad79ef5bec51da3501f5079367b625da44bf97468422d27e8e95` |
| `0xf534c–0xf534d` | 1 | `opaque_bytes_unresolved` | `1e` | `0c` | `9652595f37edd08c51dfa26567e6cd76e6fa2709c3e578478ca398d316837a7a` | `ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977` |
| `0xf56d0–0xf56d1` | 1 | `opaque_bytes_unresolved` | `1e` | `0c` | `9652595f37edd08c51dfa26567e6cd76e6fa2709c3e578478ca398d316837a7a` | `ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977` |
| `0xf56d2–0xf56d4` | 2 | `opaque_bytes_unresolved` | `ac0d` | `b80b` | `64092f06dca78a2dfb394a194e56b7222a5d4b3b746c2b6d0bb685e75b712afa` | `cd2b4698bb7d0c92d0d6f9bf41a591732ddc53473584af3792e72e88b714ad0b` |
| `0xf59e0–0xf5adc` | 252 | `opaque_bytes_unresolved` | `3a7b4bed38e69a2ca3d3ea3d21e98a082e40259a451b1808ccaaa578a730922d47afddbceda7d4438d6f724487e0e3b14680e9bf9f750e7351dfb2b58670a806c784cebaa87cc9feb758b81a60e8dec56f623e0cc61283f71a328ab913e5220b12902c349fc2a92687f9a32ec0ec30ee4608ec391079264a9af8004a7a77a1fa0507f6ce391f6534fd3775dbca701a8f3e6228206c0f0afc21539cf457be3e2aa9707e391c96a8be6fd1b3d4aeb5a5da9530a903c17dc92608e280316782c7ee06c00165645a1afee970fb95b2b919b9b4a28939559ceca69358d61d20c2b4986fc3274e46e0b99c2bf9a4f2858d3ea721f6a29d15e13d41b12ba86c` | `7553bb6c1b9a60eea60499fba99b80381a5d40b7fca5514324005f42ed593b85b65679cc885dc3cf23926a784b1ad0bd02669afd1caf95d80eec657c7c05eb61e8716a1df7880b176b62d03d422cfdd68f197a3803e4078771d1591645ebdcef7c3945c5fae7bf8260b4bf5ce8e615d84ae31d04f73f840c5583f6e4903252a2650f81f4484afadc6f4dad43b44debfb50ba1fc2099ba868082c877fb241b40da266baba8788ac698018c96fdd6f9a1f9a8d78b44f74d34a027449eba9117a03e6f4faf4b6e322b5944022df0c4c55abec1ed04abce3df23c0330f167ecc78cca8d3bdc5702a459121cfaf8e511b79c75b4bc37d1cbcc919ac279f3e` | `886a3692ea476d88aa91f22f8894f3ec36947096a8b2c51b3ebab755a09862c9` | `aeede0d72fc8f535fa5907947187d7f31e9a9935df5b44ec0a0ac9f4a8edf259` |
| `0xf5add–0xf5ae0` | 3 | `opaque_bytes_unresolved` | `4e7df2` | `c342bf` | `a3a628de1e6253d3c42ca19ea62da46cd8abfc19b5a89af03ef93c676ffdbb13` | `e640d0dcdffd91543ef6d6511d3c69891d5ba679ce3a1d87b72126f1c144610a` |
| `0x100f00–0x100f0d` | 13 | `opaque_bytes_unresolved` | `d6fc756b0d4e392338887b8a91` | `9c3c50bdd44169f13ddd74de6c` | `4db9ff850540b2b3d1878d4d7fe1694df5e4a77e3f4734912b1f1b4882219f1b` | `d1677bef8e588f08d0c502ff34e2034e443b678f2bd4b6e2aaa48e120f450dc6` |
| `0x100f0e–0x100f64` | 86 | `opaque_bytes_unresolved` | `9d546f813561c4e11ca04aa461be80dec5900390fbe4af7a772998f7fd070b2e8757a24e04e206e61b231c94a8235357bc097bbe359b58e4e33c9f986198f88316d2eaebd0a3ff199b11b77626a6452ca7623f276efd` | `03ed0762947dad49e5b1c3f119ec4543652a6cf6623ddb33ce01f59324374c99ec4f79dfceaa34cf0eeb7af231bc3c469595f9fbd18fdb581777e09e6a4f42997f0ebeb8d261ad39b6c95a0d61f44011a43738818c6f` | `4683a0be3ccc555d50c6d757a544bee19a4cb313d592c95840ca6030be82a164` | `0a5042afbda23974fdca2a04fbf71c5b9bd98d805fd086ef610be26c11a8cbec` |
| `0x100f65–0x100f6e` | 9 | `opaque_bytes_unresolved` | `9564a1d2ec395bfab1` | `2631278d3cad5e734b` | `ec07d09426b6ebedcaee1fd15009ab0caf5a5c92f354d8dc019a00dd4f8794f4` | `f40bb755bd753c9b0ecd884437d76fcd9de36c87bc239fb26e0d3e335602f6e0` |
| `0x100f6f–0x101000` | 145 | `opaque_bytes_unresolved` | `b4b6e7c3fa0440e9442ae8b77c49431440360625480f0248bcc6320dea25c15ee1424ed824e61e3feea8133f84a7164511525f3c335ab3af0e978a1f8e1a84f6c70bcbc0a9eb512773992a5cab99ccea71a8a6d269600a01d8a256819012ed4411a2c60c9da53a70897a0872396b8192dc4ddfea84da270d0ff258989a20b5add0c6840bab90944610411c8935da6f50b4` | `03f82cab58f5bfc936da77ea87de55a6d818ccc6dd75910e6d68087967fade13cbf600fc88b5a17e0998d005f4dc66f8457c9958358d5b4212b714556e16e0fb76168f673b66fe7c247867a2b7d3738d0593725e37bde576fdd13840966ad71a5bf1285ad9ac14dd04062fe9c39ee5edd43a3308c0630b2d1a16bd1061c393696c41114fe151cc7656066fbcf2046dc174` | `23d7064a5849ae961ad4645db61c837fdced18265a1c4179338298b7de6273a6` | `ae72390b1f1a6cb01c27b6f6ccc02d893e877b6d1553976d21e8096604e0edae` |
| `0x117f00–0x117f10` | 16 | `opaque_bytes_unresolved` | `a6c4877292cf3753094bbc748b3638b7` | `f051f3270b78e5fcc7ecb593f4d25562` | `82fc9a130c2b99bed612baa5239ff06047bb4748d79b24566fffbcd0cc5a37a7` | `58e3904e4adc0fdee9fab4693273632b96133dd364c17d0a929055888e4e01e6` |
| `0x117fa1–0x117fa2` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x117fa3–0x117fa4` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x117faa–0x117fab` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x117fac–0x117fae` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x117faf–0x117fb1` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x1183e0–0x118433` | 83 | `opaque_bytes_unresolved` | `0c2385c5767ca580d15e903633897dfb467492620c36a9ce30e7912ec038840e47f02b72fac432916f5ae7076444ffe66217150870d4883e240b391c6d854c789f549acbeff7ddfec80dc1536c50b6bf7adeb5` | `197f5d0d244d192a68c4f4278e6c4ad1d8de2a6eb3686fd323d5eac23e47ae41a6aaa0d0e48383d820dddcf46632bed117d29fada589ade8705764a14571f613fa527ff670fcbcf23ed76ea0ec731028581f93` | `d178fda029bd692e6d0dc01bebd3804fc19975a7763b5a658e9fe151f3182f43` | `75a84be8dc69731315ce5a6b5758b7dfdd681a4c4f0758dff04bda9aa383d182` |
| `0x118434–0x1184ce` | 154 | `opaque_bytes_unresolved` | `f11b88c913fc798b79e88a15aa46deaf34e4fb96c619f7dd95a78f0fe385abddb7ee71a7594d74840c70284934fe999590789692d509166b4f84740741c4995e2444adb33b5adc01b3d9cc94bd9d5a22a59a7fc950b9b3e550dd97604d0e18541a3a7f8531c62def2cf18c70452ad6ff12bb9183ad9e71e7b841626842675f4dff90f5b302e9e3ff9a54822810277d7507864a2d77b325c92d38` | `c62d4927d622ebe19cb82ea9719b8cd5318de6703e6d69032774a956eb202f26f01116d3912036abea222b6db024cd2e944ca3608c615bc9d730cd22a55b7632d818683f13ef89996adb23c0548a993071864f6572fecd51807f6010aa5e9ec0e6435abfd31d8c16eaacebd37f184dfbcab1e4cc420c1f24d8f1227b2fde65ddfed87d7560efdceddac9b9d7e4dd90d7c677679abe688bc03c5b` | `ff413a0dffc947c046921084fd58ff5f55c1eb6b1298b4d56ce9adb90ce24c71` | `f87f18c048dd3d5649ff66ea513e36a417125466389600fe0ade1c0ac98743ab` |
| `0x1184cf–0x1184e0` | 17 | `opaque_bytes_unresolved` | `87704f628fb477f550771b72981c857755` | `a5d8f6c1757b4e51be981ad6c4d6206417` | `0a1cdcc29358f673d805ccd9c7e4364c62e3bdb74f5cffff7ed2d4ce572430c6` | `3a95eb9365e511ca46a6e6a8e8043c62fee44fbba97ec3461550fac90f3e74a6` |
| `0x120021–0x120022` | 1 | `option_rom_bytes_unresolved` | `73` | `6d` | `043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89` | `62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a` |
| `0x120051–0x120052` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x120053–0x120054` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x12005a–0x12005b` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x12005c–0x12005e` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x12005f–0x120061` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x1200b4–0x1200b5` | 1 | `identified_text_bytes` | `34` | `37` | `4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a` | `7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451` |
| `0x120164–0x120168` | 4 | `option_rom_bytes_unresolved` | `30383134` | `36313938` | `c75eca238ec250c28443dcb5bf69f9af1d465b62ebe19ef91874801b1b29bade` | `529f951b64739ac49f4bd732fb4aef675c34fda5acedb8cc01d030cd3301c22c` |
| `0x1201ed–0x1201f1` | 4 | `option_rom_bytes_unresolved` | `6687108d` | `740f0215` | `6160650dd4fc2a4f4d1dd231e515106dff071b2b5149624ce7db87fcbd628909` | `c79128147e5c5e4aed53e2ee749a13e20b6e3ba8c9124a0d19114a943abd8aa9` |
| `0x123221–0x123222` | 1 | `identified_text_bytes` | `33` | `35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` | `ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d` |
| `0x123223–0x123224` | 1 | `identified_text_bytes` | `31` | `30` | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` |
| `0x12322a–0x12322b` | 1 | `identified_text_bytes` | `32` | `33` | `d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35` | `4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce` |
| `0x12322c–0x12322e` | 2 | `identified_text_bytes` | `3338` | `3130` | `aea92132c4cbeb263e6ac2bf6c183b5d81737f179f21efdc5863739672f0f470` | `4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5` |
| `0x12322f–0x123231` | 2 | `identified_text_bytes` | `3239` | `3433` | `35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458` | `44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a` |
| `0x12e659–0x12e65d` | 4 | `option_rom_bytes_unresolved` | `30383134` | `36313938` | `c75eca238ec250c28443dcb5bf69f9af1d465b62ebe19ef91874801b1b29bade` | `529f951b64739ac49f4bd732fb4aef675c34fda5acedb8cc01d030cd3301c22c` |
| `0x1d4200–0x1d4210` | 16 | `opaque_bytes_unresolved` | `584d34cb08f28e8696cd09c8200f6d8b` | `7c9ae8a1b03cf520ad6375ea22ef6c3e` | `98fc56e439aa18fe5d258cc15c4c593b4e9b5b75e73eb9bb2672cae22aedb4a0` | `1cb97408655d6a88161bd50c417329e1b36ccf933ed4008b974c89f3eeec58cc` |
| `0x1d42d0–0x1d4300` | 48 | `opaque_bytes_unresolved` | `207ca7c1fe25c4452f286fe016aac62598f0f47ab7fddfe482c75371345a450e9fd77b91bbdb317a848641965bc1ce8b` | `e33cf57e3640f4ca3a16cca2197850d7dd04a2b32e939c30844edef2118686246c2addac33043a29785a98a758b5f68d` | `ed6b2c902cc22bd1f6698ebc9c5b4ee16361ed1aaf5406f7dc6d2dbfac3b1ee3` | `cf7410931cb60303918001d54650ed313d29f9fdb745ebc39545c9244c503b11` |
| `0x1d433a–0x1d433b` | 1 | `opaque_bytes_unresolved` | `60` | `b9` | `8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3` | `04d6c0c946716aac894fc1653383543a91faab601302cf011607c82f06304651` |
| `0x1d47b0–0x1d47b4` | 4 | `opaque_bytes_unresolved` | `ac0dac0d` | `b80bb80b` | `40f11cfb8e01823607cd41ee77d743988f478cade1401431b441766279b6ef1e` | `f5203c6627b95d70b17d3542af629e6892c7afe58c42f7f83089a5ab4ca7b812` |
| `0x1d47b6–0x1d47b8` | 2 | `opaque_bytes_unresolved` | `ac0d` | `b80b` | `64092f06dca78a2dfb394a194e56b7222a5d4b3b746c2b6d0bb685e75b712afa` | `cd2b4698bb7d0c92d0d6f9bf41a591732ddc53473584af3792e72e88b714ad0b` |
| `0x1d5340–0x1d5346` | 6 | `opaque_bytes_unresolved` | `1e1e1e1e1e1e` | `0c0c0c0c0c0c` | `20f1a027e69979fe9fef5e8e3dd56f5e5a850bf4b96b880642eb80151a2659c5` | `7b2aa16484b6ad79ef5bec51da3501f5079367b625da44bf97468422d27e8e95` |
| `0x1d534c–0x1d534d` | 1 | `opaque_bytes_unresolved` | `1e` | `0c` | `9652595f37edd08c51dfa26567e6cd76e6fa2709c3e578478ca398d316837a7a` | `ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977` |
| `0x1d56d0–0x1d56d1` | 1 | `opaque_bytes_unresolved` | `1e` | `0c` | `9652595f37edd08c51dfa26567e6cd76e6fa2709c3e578478ca398d316837a7a` | `ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977` |
| `0x1d56d2–0x1d56d4` | 2 | `opaque_bytes_unresolved` | `ac0d` | `b80b` | `64092f06dca78a2dfb394a194e56b7222a5d4b3b746c2b6d0bb685e75b712afa` | `cd2b4698bb7d0c92d0d6f9bf41a591732ddc53473584af3792e72e88b714ad0b` |
| `0x1d59e0–0x1d5adc` | 252 | `opaque_bytes_unresolved` | `3a7b4bed38e69a2ca3d3ea3d21e98a082e40259a451b1808ccaaa578a730922d47afddbceda7d4438d6f724487e0e3b14680e9bf9f750e7351dfb2b58670a806c784cebaa87cc9feb758b81a60e8dec56f623e0cc61283f71a328ab913e5220b12902c349fc2a92687f9a32ec0ec30ee4608ec391079264a9af8004a7a77a1fa0507f6ce391f6534fd3775dbca701a8f3e6228206c0f0afc21539cf457be3e2aa9707e391c96a8be6fd1b3d4aeb5a5da9530a903c17dc92608e280316782c7ee06c00165645a1afee970fb95b2b919b9b4a28939559ceca69358d61d20c2b4986fc3274e46e0b99c2bf9a4f2858d3ea721f6a29d15e13d41b12ba86c` | `7553bb6c1b9a60eea60499fba99b80381a5d40b7fca5514324005f42ed593b85b65679cc885dc3cf23926a784b1ad0bd02669afd1caf95d80eec657c7c05eb61e8716a1df7880b176b62d03d422cfdd68f197a3803e4078771d1591645ebdcef7c3945c5fae7bf8260b4bf5ce8e615d84ae31d04f73f840c5583f6e4903252a2650f81f4484afadc6f4dad43b44debfb50ba1fc2099ba868082c877fb241b40da266baba8788ac698018c96fdd6f9a1f9a8d78b44f74d34a027449eba9117a03e6f4faf4b6e322b5944022df0c4c55abec1ed04abce3df23c0330f167ecc78cca8d3bdc5702a459121cfaf8e511b79c75b4bc37d1cbcc919ac279f3e` | `886a3692ea476d88aa91f22f8894f3ec36947096a8b2c51b3ebab755a09862c9` | `aeede0d72fc8f535fa5907947187d7f31e9a9935df5b44ec0a0ac9f4a8edf259` |
| `0x1d5add–0x1d5ae0` | 3 | `opaque_bytes_unresolved` | `4e7df2` | `c342bf` | `a3a628de1e6253d3c42ca19ea62da46cd8abfc19b5a89af03ef93c676ffdbb13` | `e640d0dcdffd91543ef6d6511d3c69891d5ba679ce3a1d87b72126f1c144610a` |

## XFX software-ROM comparison sample

The existing XFX AMDGPU debugfs capture (`58,880` bytes; SHA-256 `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d`) contains a bounded legacy PCIR image that aligns at equal length with the ASUS legacy image. The file-relative PCIR image ranges differ, so comparison is made at image-relative offset zero. It finds 591 differing bytes in 136 ranges. This is a structural comparison only: the XFX capture came from ACPI VFCT per the retained host log, its physical SPI contents are unverified, and its exact retail SKU/PCB revision are unknown.

Among 19 ATOM table records aligned by table ID and master-list index, 13 are byte-identical. 6 have the same declared length and revision but different bytes; no layout/revision mismatch is reported for this sample:

| Table | Length | Revision | Byte differences |
|---|---:|---:|---:|
| `vram_usage_by_firmware` | 48 | 2.2 | 1 |
| `smc_dpm_info` | 532 | 6.0 | 6 |
| `display_object_info` | 200 | 1.5 | 3 |
| `firmware_info` | 172 | 3.5 | 7 |
| `unclassified_table_09` | 852 | 3.3 | 1 |
| `ATOM_ROM_HEADER` | 44 | 2.3 | 8 |

These table differences include board-specific ATOM ROM header offsets and small field/body differences in FirmwareInfo, SMC/DPM v6.0, display-object, VRAM-usage, and one unclassified table. Matching table IDs, lengths and revisions make these useful comparison targets for later source research, but do not make any ASUS interpretation transferable. In particular, the XFX host's 64 active CUs cannot establish ASUS CU capability; neither byte sharing nor matching layout proves cross-flash compatibility, runtime behavior, authentication coverage, or image acceptance. Exact byte ranges and per-table hashes/statuses are preserved in JSON.

The exact-revision FirmwareInfo comparison also exposes different nonzero `pplib_pptable_id` values: ASUS has `0x00001296` at file offset `0x423b0`; the XFX software ROM has `0x0000125b` at `0x23b0`. The public v3.5 header describes a driver-sourced PowerPlay table. Current upstream [SMU14 setup](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/smu_v14_0.c) carries a nonzero PPLib ID into setup, and the [common parser](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c) can match it against entries in a v2.1 directory embedded in driver SMC firmware. This establishes a concrete driver-policy trace lead, but the firmware blobs, exact matching entries and exact R9700 runtime path are not established. It does not make the ID itself a tuning value or support cross-flashing or transferring settings.

## Region accounting

The JSON file partitions every byte of each ASUS payload and the XFX comparison file into exactly one of `decoded`, `identified_but_undecoded`, `known_padding_or_repeated_data`, or `opaque`, after applying bounded structure spans. A companion `classification` and `resolution_note` distinguishes supported fields/literals, static code candidates, identified-but-unresolved structure bodies, repeated/padding bytes and unresolved regions. `opaque` means no supported structure or reviewed code-body candidate maps that range; it does not mean the bytes are empty. Exact duplicate bytes and the EFI `0xff` tail are classified as known repeated data or padding without inferring topology or behavior. The summary below is for AS04; AS07 has the same boundaries and accounting.

| Classification | Bytes |
|---|---:|
| `opaque` | 1,797,376 |
| `identified_but_undecoded` | 115,825 |
| `known_padding_or_repeated_data` | 116,705 |
| `decoded` | 1,966 |

XFX comparison sample (`58,880` bytes):

| Classification | Bytes |
|---|---:|
| `opaque` | 0 |
| `identified_but_undecoded` | 57,971 |
| `known_padding_or_repeated_data` | 0 |
| `decoded` | 909 |

## Decoded table detail

Each decoded table below matched its exact observed revision and validated declared length or bounded variable-length array. Exact structure names and source URLs are retained in JSON. Reserved bytes remain raw; display-object record references are not followed into unvalidated nested content.

| Table | Fields or bounded interpretation | Limit |
|---|---|---|
| `umc_info` v4.0 | VRAM type `GDDR6` (`0x70`); UMC IP bounds `10/8` raw; reference clock `100.0 MHz`; ECC-capable metadata `0x00010000`; channel count/width encoding `16/4`; public-driver-derived width `256 bits. | The width is derived from current driver code, not a physical measurement; metadata does not prove active ECC correction. |
| `dce_info` v4.5 | Display caps `0x00000300`; boot display clock `62500` in 10 kHz units; DCN IP range `0–4`; max display pipe fields `4/1`. | This is VBIOS display capability/configuration metadata; it does not identify physical connector wiring or prove runtime modes. |
| `gpio_pin_lut` v2.1 | 20 bounded 8-byte GPIO assignments decoded from the 160-byte entry array. | Pin/register mapping alone does not establish board circuitry, fan control, or runtime use. |
| `vram_usage_by_firmware` v2.2 | Firmware framebuffer reservation start `0 KiB`; firmware reservation `0 KiB`; driver region-0 reservation start/size `0/0 KiB`. | Reservation metadata, not memory timing, capacity, or performance tuning. |
| `display_object_info` v1.5 | 4 bounded 16-byte display paths decoded; 128 trailing bytes remain identified but undecoded. | Nested record offsets are range-checked and reported, not dereferenced. |

## Customization opportunity assessment

Each proposal separates the evidence, controlling layer, plausible benefit, confidence, risk, investigation decision, editing decision, and evidence still needed.

### Fan curve and acoustics

- **Field or region:** AS04/AS07 changed opaque bytes; ASUS vendor note; SMC/DPM v6.0 (532 bytes) remains undecoded
- **Current value:** Vendor states AS07 refines the fan curve; no decoded fan field is identified and all discovered ATOM records are byte-identical between payloads.
- **Controlling layer:** Potentially VBIOS policy, SMU firmware, driver policy, and board fan/thermal circuitry; current payload does not identify the controlling bytes.
- **Plausible benefit:** A measured lower-noise profile at acceptable temperatures, or improved thermal stability if the stock profile is inadequate.
- **Confidence:** Medium that fan behavior was the vendor update intent; low that any changed range maps to fan control or predicts behavior.
- **Risk:** A guessed edit can raise GPU, hotspot, memory, or VRM temperatures; a faster curve adds noise and fan wear.
- **Investigation:** GO for evidence collection and measurement on the identified card.
- **Editing:** NO-GO until the field, signature/integrity coverage, accepted-image path, board limits and independent recovery are established.
- **Evidence needed:** Exact ASUS SKU/PCB and matching-card stock/update images; supported SMC/DPM schema; fan RPM, acoustic, GPU/hotspot/VRM temperatures and sustained clocks under repeatable loads.

### Core clock, voltage, power and efficiency

- **Field or region:** FirmwareInfo v3.5 PPLib ID 0x00001296; null PowerPlayInfo pointer; SMC/DPM v6.0 opaque
- **Current value:** No directly decoded general board clock, voltage, or power limit. FirmwareInfo's boot clock/voltage slots are reserved; PPLib ID is nonzero.
- **Controlling layer:** Driver-sourced PowerPlay policy, SMU firmware, and board power delivery; an exact ASUS control split is not established.
- **Plausible benefit:** Lower energy per workload or improved sustained throughput only if a measured clock, power, or thermal limit is the bottleneck.
- **Confidence:** High for the table fields and PPLib source comment; low for any ASUS runtime consequence.
- **Risk:** Instability, elevated current/temperature, workload errors, or reduced reliability.
- **Investigation:** GO for workload profiling and source tracing.
- **Editing:** NO-GO: no revision-matched general limit field or safe acceptance path is established.
- **Evidence needed:** Exact-board driver/SMU trace, measured power and clocks under target workloads, board electrical limits, matching policy schema and recovery evidence.

### Memory timing, voltage and ECC

- **Field or region:** UMC v4.0: GDDR6 code 0x70; channel_num=16; channel_width encoding=4; umc_config1=0x00010000; VRAMInfo master pointer is null
- **Current value:** UMC v4.0 metadata is decoded; it contains no memory timing table. ECC-capable bit is set in this payload; this does not demonstrate runtime correction. DRAM population and routing are unknown.
- **Controlling layer:** SMU/driver policy and UMC firmware, plus fitted DRAM, board routing, power delivery and silicon support.
- **Plausible benefit:** Potential memory throughput or energy improvement only for a demonstrated memory-bound workload; ECC may support error resilience when the full stack and hardware enable it.
- **Confidence:** High for exact UMC fields; low for physical configuration, tuning headroom, and ECC runtime behavior.
- **Risk:** Silent data corruption, memory instability, elevated temperature, or board/DRAM damage.
- **Investigation:** GO for identifying memory components and tracing ECC reporting; memory tuning only after baseline validation.
- **Editing:** NO-GO: no timing/voltage field or verified ASUS memory configuration is established.
- **Evidence needed:** Exact DRAM ICs/topology and board revision, revision-matched timing schema, driver and SMU behavior, memory-correctness tests, ECC status/error counters under workload, and recovery route.

### CU / stream-processor unlock

- **Field or region:** gfx_info v3.1 at 0x42634 (136 bytes), body not decoded
- **Current value:** No ASUS active-CU count or enable mask is exposed by a revision-matched definition in this audit.
- **Controlling layer:** Potentially fused/harvested silicon resources and driver/runtime topology; configurable policy cannot create fused-off or physically absent units.
- **Plausible benefit:** More usable compute only if the exact card has functional disabled units and an authorized policy path that permits them.
- **Confidence:** High that this payload does not safely expose a v3.1 CU field; unknown ASUS physical or fused capacity.
- **Risk:** Invalid resource topology can prevent initialization or cause instability; an apparent count change cannot establish functional hardware.
- **Investigation:** GO for research into public definitions and exact-card read-only resource enumeration.
- **Editing:** NO-GO: no ASUS unlock field, candidate image, or un-fused disabled resources have been demonstrated.
- **Evidence needed:** Exact ASUS ASIC/card identity, revision-matched v3.1 definition if available, public/validated driver path, runtime CU topology and fuse/harvest evidence.

### Feature gates and ECC enablement

- **Field or region:** FirmwareInfo v3.5 capability 0x00024000; UMC v4.0 umc_config1 0x00010000
- **Current value:** The public dynamic-boot-config capability is set; another capability bit is unnamed. UMC ECC-capable metadata is set. Neither field establishes a user-facing unlock or active correction behavior.
- **Controlling layer:** Firmware capability metadata, driver/runtime policy, SMU/PSP firmware, fuses and OS support; the ASUS payload does not reveal the complete gate chain.
- **Plausible benefit:** A supported feature could become available only where required hardware and every software/firmware gate already permit it.
- **Confidence:** High for named bits and raw values; low for their availability or effect on this ASUS board.
- **Risk:** Changing unknown flags may block initialization, weaken reliability, or misrepresent unsupported hardware.
- **Investigation:** GO for tracing a specific requested feature and collecting supported runtime evidence.
- **Editing:** NO-GO: do not edit an unidentified capability or assume ECC, virtualization, or policy behavior from a bit alone.
- **Evidence needed:** Trace one concrete feature through exact board, driver, SMU/PSP, OS support and silicon capability; verify runtime behavior with an appropriate workload.

### Display configuration and GOP

- **Field or region:** DCE v4.5, display-object v1.5, and decompressed GOP PE structure
- **Current value:** Display metadata is decoded; the bounded GOP stream decompresses to an AMD64 EFI boot-service-driver PE. Static disassembly shows indirect function-pointer calls, but their targets and display semantics remain unresolved.
- **Controlling layer:** VBIOS display tables, embedded GOP code, driver policy, display engine silicon, and physical connectors.
- **Plausible benefit:** Correct a reproducible output compatibility issue; no general performance benefit is established.
- **Confidence:** High for decoded tables and PE structure; low for GOP behavior or actual ASUS output mapping.
- **Risk:** Loss of pre-OS output, unsupported mode selection, or broken display initialization.
- **Investigation:** GO only for a specific display issue or required mode.
- **Editing:** NO-GO without a demonstrated defect, matching board evidence, integrity coverage and recovery.
- **Evidence needed:** Exact ASUS card and connector layout, supported display record definitions, a static trace to the relevant GOP path, and a reproducible display fault.

## Revision-aware modification/control matrix

This decision matrix is ASUS-specific. Target ranks prioritize further investigation based on the available static evidence; they do not estimate success or approve editing. Board identity and integrity are a cross-cutting gate, so that row has no target rank. Raw observations include local offsets or table hashes and definition sources where available. XFX evidence is explicitly marked as a separate comparison observation.

### Fan behavior and acoustics

**Target rank:** 1 (higher investigation priority). Vendor release note names this update area; the byte-to-field mapping and runtime result remain unproven.

**Artifact scope:** ASUS AS04/AS07 only

**Raw evidence and sources:**
- `smc_dpm_info` v6.0 at `0x42420`, 532 bytes, SHA-256 `be125c779843943029355edf444ef6ffb30eb213c670a42f57a77ae8d87e25cd`; The checked Linux ATOM header and AMDGPU parser source contain no smc_dpm_info v6.0 definition or parser. The 532-byte body remains undecoded; older SMC/DPM layouts are not applied. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `gpio_pin_lut` v2.1 at `0x41a88`, 164 bytes, SHA-256 `2665e512e2e36de18518ffe532b03185adae750dc05a6ff4a54f01bbc90a07eb`; Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- 57 changed ranges remain outside supported decoded fields; none is assigned to fan policy by a public definition.
- AS07 refines the fan curve for a quieter profile (vendor statement, not a byte mapping or runtime result). Source: [https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G)
- **Likely control layer:** VBIOS policy, SMU firmware, driver policy, board fan/thermal circuitry
- **Plausible benefit:** A measured lower-noise profile at acceptable GPU, memory, and VRM temperatures, or better sustained clocks if cooling is the bottleneck.
- **Confidence:** Medium for the vendor-stated update purpose; low for any byte-to-fan mapping or runtime result.
- **Risk:** An unsupported curve could raise component temperatures; a faster curve increases noise and fan wear.
- **Investigation:** GO for exact-card identification and read-only source/behavior tracing.
- **VBIOS edit:** NO-GO until the field and integrity boundary are known, recovery is demonstrated, and the change is accepted on the exact card.
- **Evidence still needed:** Exact ASUS SKU and PCB identity; Revision-matched fan/SMU definition; Same-board AS04/AS07 association; Fan RPM, noise, temperatures, and sustained clocks

### Core clocks, power, and efficiency

**Target rank:** 2 (higher investigation priority). Potential workload value is measurable, but the relevant ASUS policy and general limit fields are not identified.

**Artifact scope:** ASUS payload policy plus generic public definitions; no runtime ASUS conclusion

**Raw evidence and sources:**
- `bootup_clock_reserved` at 271228: raw `0000000000000000`; decoded value `[0, 0]`; definition `atom_firmware_info_v3_5` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `bootup_voltage_reserved` at 271248: raw `0000000000000000`; decoded value `[0, 0]`; definition `atom_firmware_info_v3_5` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `pplib_pptable_id` at 271280: raw `96120000`; decoded value `"0x00001296"`; definition `atom_firmware_info_v3_5` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `smc_dpm_info` v6.0 at `0x42420`, 532 bytes, SHA-256 `be125c779843943029355edf444ef6ffb30eb213c670a42f57a77ae8d87e25cd`; The checked Linux ATOM header and AMDGPU parser source contain no smc_dpm_info v6.0 definition or parser. The 532-byte body remains undecoded; older SMC/DPM layouts are not applied. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `PowerPlayInfo master pointer` at unknown offset: raw `None`; decoded value `null`; definition `none` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- **Likely control layer:** driver-sourced PowerPlay policy, SMU firmware, board power delivery, runtime controls
- **Plausible benefit:** Lower energy per workload or higher sustained throughput only if measurements identify a clock, power, or thermal bottleneck.
- **Confidence:** High for matched FirmwareInfo v3.5 field meanings; low for exact-board runtime control behavior.
- **Risk:** Instability, overcurrent, thermal stress, workload errors, or reduced reliability.
- **Investigation:** GO for profiling and source tracing.
- **VBIOS edit:** NO-GO: no revision-matched general board limit or supported edit route is established.
- **Evidence still needed:** Exact-board electrical limits; Active driver/SMU policy source; Repeatable workload power and clock telemetry; Recovery and accepted-image route

### Memory configuration, timing, and ECC

**Target rank:** 3 (higher investigation priority). UMC metadata is decoded, while timing controls and active ECC behavior are not established.

**Artifact scope:** ASUS UMC v4.0 only; XFX runtime observations remain separate

**Raw evidence and sources:**
- `vram_type` at 272086: raw `70`; decoded value `"0x70"`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `mem_refclk_10khz` at 272088: raw `10270000`; decoded value `10000`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `umc_config1` at 272112: raw `00000100`; decoded value `"0x00010000"`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `channel_num` at 272124: raw `10`; decoded value `16`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `channel_width` at 272125: raw `04`; decoded value `4`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `umc_info` v4.0 at `0x426bc`, 84 bytes, SHA-256 `8cdee8f64946e19e894e679faac505b860cff5dff2517d2a45faab987f43a27a`; Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- **Likely control layer:** UMC/SMU firmware, driver policy, fitted DRAM, PCB routing, board power delivery, silicon support
- **Plausible benefit:** Memory throughput or energy improvement only for a measured memory-bound workload; ECC can support resilience where hardware and software enable it.
- **Confidence:** High for the revision-matched metadata; low for ASUS DRAM population, timing headroom, and active correction behavior.
- **Risk:** Memory corruption, instability, overheating, or damage to the memory subsystem.
- **Investigation:** GO for component identification and ECC reporting trace.
- **VBIOS edit:** NO-GO: this UMC table has no decoded timing/voltage controls and its ECC bit is capability metadata.
- **Evidence still needed:** Exact DRAM and PCB topology; Revision-matched timing definition; Driver and SMU behavior; Memory-correctness workloads and ECC error counters

### Display, GOP, and pre-OS output

**Target rank:** 4 (higher investigation priority). Exact display structures and GOP code are mapped; relevance depends on a specific compatibility fault.

**Artifact scope:** ASUS DCE/display tables and decompressed EFI/GOP image

**Raw evidence and sources:**
- `dce_info` v4.5 at `0x419b4`, 212 bytes, SHA-256 `b65d753efc91bce3a9f3a84bc27ef46afc93551236dff3b297f0225b4f7467f6`; Decoded only with a bounded range and exact public revision-specific definition; reserved or trailing bytes remain raw where applicable. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `display_object_info` v1.5 at `0x422ac`, 200 bytes, SHA-256 `4d57403033b75af2f442e34356128d4b9618d5be679823a447782683baec2eba`; The exact v1.5 path-array header and four entries are decoded. The remaining 128 bytes are inside the declared table but have no exact matched nested-record definition in the checked source; they remain identified but undecoded. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- Embedded GOP: decompressed_pe_validated; output SHA-256 `77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b`; PE `AMD64`/`EFI boot service driver`; certificate directory range `90784+9776`; candidate Authenticode SHA-256 `77b66e1ac7a2fb9a6bc3cd695376ec055a7edd7378907b65d312406f3f6078f5`, extra data `0x162a0–0x162a0`, PKCS#7 check `pkcs7_signer_signature_and_pe_image_digest_verified`; signer-chain trust, timestamp and Windows policy were not evaluated. Source: [https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
- **Likely control layer:** VBIOS display tables, embedded GOP code, display driver, display engine silicon, physical connectors
- **Plausible benefit:** Resolve a reproducible pre-OS display or mode compatibility problem; no general performance gain is established.
- **Confidence:** High for bounded PE and display-table structure; low for connector wiring and actual behavior.
- **Risk:** Loss of pre-OS display or broken mode selection/initialization.
- **Investigation:** GO only for a concrete display requirement or fault.
- **VBIOS edit:** NO-GO without a demonstrated defect, exact-board evidence, integrity coverage, and recovery.
- **Evidence still needed:** Exact connector layout; Specific reproducible display issue; Static code trace for the relevant path; Accepted-image route and recovery

### Feature gates and ECC enablement

**Target rank:** 5 (higher investigation priority). Named capability metadata exists, but the complete feature gate chain and runtime effects are unknown.

**Artifact scope:** ASUS FirmwareInfo capability bits and UMC ECC-capability metadata

**Raw evidence and sources:**
- `firmware_capability` at 271236: raw `00400200`; decoded value `"0x00024000"`; definition `atom_firmware_info_v3_5` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- `umc_config1` at 272112: raw `00000100`; decoded value `"0x00010000"`; definition `atom_umc_info_v4_0` Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- The dynamic_boot_cfg_enable bit is named in the matched public definition; bit 0x00004000 remains unnamed. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- **Likely control layer:** VBIOS metadata, driver/runtime policy, SMU/PSP firmware, silicon fuses, OS support
- **Plausible benefit:** A feature could become available only when required hardware and every firmware/software gate already supports it.
- **Confidence:** High for raw values and named bits; low for any unlock or active ECC behavior.
- **Risk:** Changing an unknown bit can break initialization or misrepresent unsupported hardware.
- **Investigation:** GO for tracing one supported feature at a time.
- **VBIOS edit:** NO-GO: do not edit unnamed flags or equate ECC capability with active correction.
- **Evidence still needed:** One concrete feature request; Full driver/SMU/PSP/OS gate trace; Exact-card capability evidence; Workload validation

### CU and stream-processor availability

**Target rank:** 6 (higher investigation priority). The ASUS GFX_INFO body has no exact public revision match; fuses and runtime topology are unknown.

**Artifact scope:** ASUS GFX_INFO v3.1 body; XFX CU count is not transferred

**Raw evidence and sources:**
- `gfx_info` v3.1 at `0x42634`, 136 bytes, SHA-256 `ae4c3ddcc101afb3d2e86b6eeb3a6dbbdba2579529e8d79c94832049049ddde4`; The checked Linux header defines GFX_INFO v3.0, not v3.1, and the driver union/parser handles v2.2, v2.4, v2.7, and v3.0. No v3.1 CU count or mask is inferred. Source: [https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h)
- Existing XFX host evidence reports 64 active CUs for an XFX-subsystem device only. Source: `bios/xfx-r9700-0000-03-00-0/CARD.md`.
- **Likely control layer:** silicon fuses/harvest state, GPU initialization, driver/runtime topology
- **Plausible benefit:** More usable compute only if this exact ASUS ASIC contains functional disabled units and a supported policy exposes them.
- **Confidence:** High that public current Linux definitions do not safely expose this v3.1 body; unknown ASUS fused topology.
- **Risk:** A false resource count can prevent initialization or cause unstable execution; a VBIOS cannot create absent or fused-off units.
- **Investigation:** GO for source tracing and exact-card read-only enumeration.
- **VBIOS edit:** NO-GO: no CU enable field or functional disabled resources are established.
- **Evidence still needed:** Exact ASUS ASIC/card; Revision-matched GFX v3.1 definition; Read-only runtime topology; Fuse/harvest evidence

### Board identity and integrity metadata

**Target rank:** Prerequisite gate; not a modification target. Cross-cutting provenance and integrity gate, not a modification target.

**Artifact scope:** ASUS image strings, PCIR metadata, legacy checksum and EFI PE certificate table

**Raw evidence and sources:**
- Literal identity/version strings: `[{"confidence": "high for the string value; semantics remain limited to the label", "evidence": "literal ASCII bytes", "label": "asus_vbios_part", "length": 16, "offset": 262256, "value": "115-G287BP00-100"}, {"confidence": "high for the string value; semantics remain limited to the label", "evidence": "literal ASCII bytes", "label": "asus_rom_version", "length": 76, "offset": 262304, "value": "7551OG.23.8.0.68.AS04"}, {"confidence": "high for the string value; semantics remain limited to the label", "evidence": "literal ASCII bytes", "label": "board_string", "length": 38, "offset": 262514, "value": "ASUS_G28702_XTW_32GB_PS_APM108117_300W"}, {"confidence": "high for the string value; semantics remain limited to the label", "evidence": "literal ASCII bytes", "label": "asus_vbios_part", "length": 16, "offset": 1179760, "value": "115-G287BP00-100"}]` (up to four shown).
- Legacy image byte-sum records: `[{"checksum_valid": true, "image_index": 0, "length": 58880, "offset": 262144, "sum_mod_256": 0}, {"checksum_valid": true, "image_index": 2, "length": 58880, "offset": 1179648, "sum_mod_256": 0}]`; Byte-sum checks are structural integrity only; they do not establish cryptographic acceptance.
- `{"efi_authenticode_sha256_analysis": {"algorithm": "SHA-256", "candidate_digest_occurs_in_pkcs_signed_data_record": true, "candidate_image_digest": "77b66e1ac7a2fb9a6bc3cd695376ec055a7edd7378907b65d312406f3f6078f5", "certificate_table_size_bytes": 9776, "cryptographic_verification": {"authenticode_signature_verified": true, "candidate_image_digest": "77b66e1ac7a2fb9a6bc3cd695376ec055a7edd7378907b65d312406f3f6078f5", "chain_validation": "not performed; OpenSSL was invoked with`
- `AI-PRO-R9700_default.exe`: RAR5 marker at `0x6b600`, last section raw end `0x6b600`, overlay length 6039440 bytes before certificate offset `0x62dd90`; candidate SHA-256 `e468e856b4f85ee85e15d38af21dce05c1b36c88b71f533b3ca6d6b8ed150ee5`, raw digest-byte occurrence in PKCS#7 record `True`. The RAR5 marker is at the first pre-certificate overlay byte. Microsoft's linked Authenticode_PE step 14 hash stream covers the pre-certificate overlay; OpenSSL verifies the included PKCS#7 signer signature and the signed SPC image digest matches the calculated PE digest. Certificate-chain trust, timestamps, Windows policy, archive behavior and GPU-side image acceptance are not established. Source: [https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
- `AI-PRO-R9700_update.exe`: RAR5 marker at `0x6b600`, last section raw end `0x6b600`, overlay length 6068592 bytes before certificate offset `0x634f70`; candidate SHA-256 `7d72aa285ddf1011ff7be004b04da1bcd516187098b83f06c57fe8d628cef86f`, raw digest-byte occurrence in PKCS#7 record `True`. The RAR5 marker is at the first pre-certificate overlay byte. Microsoft's linked Authenticode_PE step 14 hash stream covers the pre-certificate overlay; OpenSSL verifies the included PKCS#7 signer signature and the signed SPC image digest matches the calculated PE digest. Certificate-chain trust, timestamps, Windows policy, archive behavior and GPU-side image acceptance are not established. Source: [https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
- **Likely control layer:** option-ROM metadata, PE/Authenticode signing metadata, GPU/PSP authentication, host updater policy
- **Plausible benefit:** Correctly identify a board/image and distinguish structural checks from signed-image enforcement; identity edits have no demonstrated benefit.
- **Confidence:** High for literal strings, PCIR bounds, checksums, updater/GOP PE signer-signature math and calculated PE digest match; unknown for signer trust, Windows policy and GPU-side VBIOS authentication or acceptance.
- **Risk:** Identity mismatch or integrity changes can cause rejection, failed initialization, or misattributed evidence.
- **Investigation:** GO for provenance and authentication boundary research.
- **VBIOS edit:** NO-GO: no identity change or custom-signing route is justified.
- **Evidence still needed:** Physical board labels and PCB revision; Signer trust and platform-policy evaluation if relevant; GPU-side VBIOS coverage/enforcement evidence; Independent recovery


### CU / stream-processor audit

ASUS `gfx_info` is revision 3.1 at `0x42634`, length 136; its body is not decoded. The checked Linux atomfirmware.h contains atom_gfx_info_v3_0 but no v3.1 definition. The public amdgpu driver union includes v2.2, v2.4, v2.7 and v3.0; its get_gfx_info path accepts v3.0 content 0 and v2.4/v2.7, so this observed v3.1 table exposes no safely decoded CU count or mask in this analysis.

The public gfx_info v3.0 definition includes maximum topology/configuration fields such as max_cu_per_sh, which are not by themselves proof of enabled units. Actual available resources require exact-card driver/runtime topology plus silicon fuse/harvest state; physically absent resources cannot be supplied by a VBIOS policy change. The repository's 64-active-CU observation is for an XFX-subsystem device only. It is not used to infer ASUS hardware capability.

**Investigation:** GO: continue static source tracing and, only after exact ASUS card identification, compare read-only runtime CU topology with hardware/ASIC evidence. **Editing:** NO-GO: no ASUS CU unlock field or candidate image is established; editing cannot restore fused-off or physically absent resources.

The updater and GOP PE PKCS#7 signer signatures and signed PE image digests verify in the static checks recorded above. Signer-chain trust, timestamps and Windows policy were not evaluated. GPU-side VBIOS signature coverage, enforcement and accepted-image behavior remain unknown. No candidate VBIOS image was produced. The XFX software dump was not used to infer ASUS compatibility.

A field value by itself does not show whether it is a hard limit or a default request. To distinguish them, compare same-board stock and official-update images, trace the active driver/SMU source, measure sustained behavior and telemetry under a repeatable workload, and identify board electrical/thermal limits and relevant silicon fuses.

## Four-area static follow-up (2026-10-19)

This addendum records the new cross-layer leads for clocks/power, memory/ECC, CU availability and feature gates. It does not change the raw ROM classification above or associate the ASUS package with a physical card.

- **Runtime power controls:** Current Linux exposes `amdgpu.ppfeaturemask`; the generic default `0xfff7bfff` disables OverDrive (bit 14) and GFX DCS (bit 19). The shared feature enum assigns `0x4000` to OverDrive in a driver namespace separate from ATOM FirmwareInfo's unknown `0x00004000`. AMD's R9700 ROCm/PyTorch guide (Rev. 2.0) describes a compute power profile favoring sustained clocks/higher power limits and an internal-memory bandwidth diagnostic. These are runtime characterization leads, not device-specific setting advice. The guide's commands were not run.
- **Read-only voltage and clock diagnostics:** AMD SMI 27.1.0's [Python API](https://rocmdocs.amd.com/projects/amdsmi/en/latest/reference/amdsmi-py-api.html) documents `amdsmi_get_power_info` (power, power limit and GFX/SOC/memory voltages where supported), `amdsmi_get_gpu_metrics_info` (current clocks, voltages and related metrics where exposed), `amdsmi_get_clk_freq` (supported clock levels and current index), `amdsmi_get_gpu_mem_overdrive_level`, `amdsmi_get_gpu_volt_metric`, and `amdsmi_get_gpu_od_volt_info` (V/F curve points and SCLK/MCLK ranges; `num_regions=0` means no curve support). Several are unsupported in VM guests. These APIs offer a read-only way to characterize a matching card and distinguish requested values from current telemetry; R9700 exposure is unverified, and driver/library mismatches can make metrics unavailable or `N/A`. No query was run.
- **Telemetry version matching:** AMD SMI 27.2.0 [installation documentation](https://rocmdocs.amd.com/projects/amdsmi/en/latest/install/install.html) says the library obtains metrics through `amdgpu` and that older/newer driver/library pairings can make fields unavailable or return `N/A`. Its [CLI documentation](https://rocmdocs.amd.com/projects/amdsmi/en/develop/how-to/amdsmi-cli-tool.html) specifically notes that an unsupported `gpu_metrics` layout prevents parsing related metrics. Any clock, power or voltage observation would need the driver and AMD SMI versions recorded and compatible; no R9700 telemetry query was run.
- **PPLib source selection:** Current Linux documents `smu_pptable_id` with automatic (`-1`), VBIOS (`0`) and positive driver soft-table ID modes; SMU14 setup honors the override. Its separate PowerPlay microcode-table path also depends on PSP loading, SCPM, non-SR-IOV state and supported IP versions. This is a software selection/trace lead, not a VBIOS field. Exact matching firmware entries and the exact R9700 vendor-kernel path are unknown; no selector was changed.
- **Conditional SMU path:** Current upstream `amdgpu_smu.c` dispatches MP1 14.0.2/14.0.3 to the SMU 14.0.2 implementation. Its setup fetches a combo PowerPlay table from PMFW and gates OverDrive/fan availability from feature masks in that table. It does not use the generic `smu_v14_0_setup_pptable` PPLib-ID path. A newer external R9700 report logs MP1 14.0.0; current upstream dispatches that version to the separate `smu_v14_0_0` implementation. The 14.0.2/14.0.3 behavior therefore cannot be assumed for that reported card, much less for an unassociated ASUS payload. The ASUS card's MP1 revision and executed runtime path remain unknown, so its FirmwareInfo ID is still a tracing lead rather than a demonstrated active table selector.
- **14.0.0 interface and voltage telemetry:** Current upstream [`smu_v14_0_0_ppt.c`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0_0_ppt.c) uses driver interface `0x7` for its generic MP1 14.0.0 path and marks that path APU-oriented; the shared [SMU 14.0 header](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/pm/swsmu/inc/smu_v14_0.h) assigns `0x2e` to 14.0.2. In that 14.0.0 source, the VDDGFX and VDDSOC sensor cases return zero. External issue #9299 reports an R9700 with MP1 14.0.0 and PMFW interface `0x33`; that report does not establish that this current generic APU-oriented source or its voltage telemetry matches the R9700's driver/firmware pair. It is a source-matching and telemetry-quality lead, not a decoded ROM field.
- **SMU interface reports:** Current upstream SMU 14.0.2 still expects driver interface `0x2e`; R9700 issue logs report PMFW `0x32` or `0x33`. An Aug 2026 three-card report includes two ASUS cards with VBIOS part `115-G287BP00-100` and one ASRock card at PMFW 104.76/interface `0x33`. Its author says two ASUS fan curves initially tracked temperature, then a later run showed about 2,350–2,520 RPM at 99–101 °C junction versus roughly 3,500 RPM near 65 °C, around 300 W, with runtime PM held active; one card later stopped answering SMU requests. The local AS04/AS07 images contain the same part label, but the report gives no ROM hash or version to tie it to either payload. Other reports conflict on whether `gpu_od` exists, and an AMD contributor says version mismatches can be nonfatal. A community one-line driver patch proposes `0x33` and claims R9700 improvements, but is not upstream validation. These reports do not prove the mismatch or VBIOS caused the fan behavior.
- **Fan control:** The current generic SMU 14.0.2 source names fan-curve anchors, minimum PWM, target temperature, acoustic thresholds and zero-RPM controls among OverDrive features; Linux documents these as staged runtime controls requiring `c` to commit. The exact ASUS MP1/SMU path and exposure of `gpu_od` remain unknown. A user reports ASUS AS07 lowers minimum fan speed from 30% to 12% after a full power cycle; the official package changelog says the curve was refined, but this user's measurement is not tied to the local payload hash and no changed byte maps to the fan behavior. This makes fan behavior the clearest candidate to investigate, not a known custom-ROM byte to edit.
- **Additional runtime reports:** An AMD contributor reproduced an R9700 s2idle SMU/DPM resume problem and said a driver fix was submitted. A separate ROCm 7.14 issue reports roughly 16–18 W additional aggregate idle power across three R9700s using HIP versus Vulkan with a resident model; this is a workload/backend comparison, not a VBIOS measurement. The migrated [ROCm issue #9228](https://github.com/ROCm/TheRock/issues/9228), formerly #6347 in the legacy repository (the same report, not an independent case), describes process-start-dependent throughput on one R9700: slow and fast runs show similar SCLK, forcing high DPM did not prevent the state transition, and manually pinning the highest DPM level reduced boost. Later comments report the split with some graph/attention configurations but not another tested configuration; authors suspect process/queue or capture initialization but do not identify a cause. A newer [issue #9299](https://github.com/ROCm/TheRock/issues/9299) reports SMU message timeouts and MES queue failures ending in full host hangs on dual R9700s at PMFW 104.79/interface `0x33`; a second contributor reports a similar failure with another R9700 firmware string. The first report logs MP1 14.0.0, which current upstream dispatches to `smu_v14_0_0` rather than `smu_v14_0_2`; its implementation must not be substituted for the reported device path. The first report lists normal temperatures and a 230 W cap, and correlates failures with bursty clock/power changes alongside SDMA/PCIe traffic without controlled isolation. These are runtime/driver/firmware compatibility leads from other cards, not evidence of a defect or edit target in the unassociated ASUS ROMs.
- **Memory timing and voltage:** Current upstream [`amdgpu_atomfirmware_get_umc_info()`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c#L2978-L3058) accepts UMC format/content revision 4.0 and computes `channel_num * (1 << channel_width)`, giving 16 * 16 = 256 bits for these bytes; this is a code interpretation, not a physical measurement. The same driver parser’s [`amdgpu_atomfirmware_mem_ecc_supported()`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c#L3333-L3455) treats `ENABLE_ECC_CAPABLE` as memory-ECC capability and separately derives `ras_default_ecc_enabled` from `DEFAULT_MEM_ECC_ENABLE`; this payload sets the former and leaves the latter clear. Current public ATOM headers define GDDR6 timing/init structures in other `vram_info` revisions, but the ASUS `vram_info` pointer is null; `voltageobject_info` is null as well. Do not apply those layouts to this ROM. The generic SMU 14.0.2 feature map names `VMEMP_SCALING` and `VDDIO_MEM_SCALING`, but this does not establish R9700 support or provide values. Upstream AMDGPU/PSP also has separate long/two-stage memory-training paths for resume/cold boot; they are runtime training controls, not editable timings established here. AMD SMI documents read-only queries for memory-clock overdrive percent, memory DPM frequency levels/current index, memory voltage where exposed, and the voltage/frequency curve's MCLK range. These do not expose DRAM timing registers, and none confirms R9700 support. Guest VMs cannot retrieve host ECC counts; no query was run.
- **Memory overdrive behavior on other boards:** The external [two-card Gigabyte report](https://github.com/daimonionnn/amd-r9700-vllm-and-tuning-toolkit/blob/main/docs/r9700-mem-vendor-bios-variance.md) and its [OC/UV follow-up](https://github.com/daimonionnn/amd-r9700-vllm-and-tuning-toolkit/blob/main/docs/r9700-oc-uv-findings.md) report no Hynix gain from 1349 MHz MCLK, and harmful results on a Samsung sample. With amdgpu DKMS 6.19.4, 1300/1350 MHz `OD_MCLK` requests read back as accepted while the DPM table stayed capped at 1258 MHz; sampled load clocks topped at 875 MHz, and a later A/B reports a 6.6% decode loss when MCLK topped at 1124 MHz while prefill remained within noise. This is a third-party runtime result from a specific card/driver/workload, not a timing-table decode or evidence for ASUS ROM edits. It does show why an OD readback is not proof of the effective memory clock.
- **Unverified tuning reports:** A community R9700 report describes driver-version-dependent MCLK overdrive behavior, failed or misleading requested-value readback, cooling-dependent power observations, and workload-specific undervolt gains and failures. It also says a 330 W cap that had previously failed above 300 W later applied after cooler service, with a reported 393 W peak and roughly 320 W average; the author cannot tell whether service changed firmware or hardware. A separate personal report describes a workload-specific 210 W limit with no reported throughput loss but silent errors/hangs under undervolting. These reports are not controlled or mapped to ASUS and provide no safe transfer values. They strengthen the case for recording effective clocks, workload correctness and thermal state before discussing persistence.
- **CU path:** Current upstream GFX 12 code constructs CU information from hardware-visible topology and inactive masks. The Linux `amdgpu.disable_cu` parameter adds a software disable mask; it offers no path to reactivate hardware-fused/inactive units. Neither this generic source path nor the host's 64-CU XFX observation proves ASUS topology or a VBIOS unlock.
- **Probe-time RAS initialization path:** Current upstream [`amdgpu_ras_feature_enable_on_boot()`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.c#L3743-L3826) branches on internal software flag `AMDGPU_RAS_FLAG_INIT_BY_VBIOS`, defined as bit 0 in [`amdgpu_ras.h`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.h#L2240-L2246), and sends PSP RAS TA enable/disable commands through a special probe-time path. The source does not map this driver-internal flag to ASUS ATOM capability `0x00004000` or prove GECC behavior; the exact R9700 branch remains unknown. This is distinct from PSP dynamic-boot-config GECC selection below.
- **RAS versus GECC:** Current upstream parameter docs define `ras_enable` as a driver RAS gate, but pinned PSP RAS initialization has a conditional next-boot effect: on a dynamic-boot-config device, if UMC RAS is unsupported (including a path where `ras_enable`/`ras_mask` disables it), PSP may set GECC off for the next boot; if RAS is supported and GECC is off, it may request GECC for the next boot. A separate R9700 runtime log says `ras_enable=1` can enable GECC in the next boot cycle, consistent with that code path but not proof of cause or correction. The ASUS capability advertises dynamic boot configuration, but exact device execution is unknown. This is not an immediate VBIOS ECC switch. AMD SMI 27.1.0 documents read-only `amd-smi metric -e` totals for correctable, uncorrectable and deferred errors, per-block counts and live monitoring. Its [Python API](https://rocmdocs.amd.com/projects/amdsmi/en/latest/reference/amdsmi-py-api.html) exposes `amdsmi_get_gpu_ecc_enabled` for the enabled-block mask, `amdsmi_get_gpu_ecc_status` for per-block ECC status, `amdsmi_get_gpu_ras_block_features_enabled` for separate RAS block states, and `amdsmi_get_gpu_ras_feature_info` for RAS version/schema information. The Python API marks ECC-state and RAS-block-status calls unsupported in VM guests; AMD SMI changelog says guest VMs cannot retrieve host ECC counts, though `amd-smi static --ras` can display enabled/disabled RAS features on host cards. That guest view is RAS feature state, not proof of external-memory GECC correction. AMD notes ECC enablement is independent of counter support; current AMD SMI docs also warn that mismatched driver/library versions can make fields unavailable or `N/A`. Current upstream [AMDGPU RAS code](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ras.c) separately documents debugfs `ras_ctrl` enable/disable operations on supported blocks such as UMC, with status visible through `ras/features`. This is a driver-side RAS feature control, not a direct VBIOS or GECC switch; no control or injection was run. Hardware/driver support is not established for the exact cards here; no query was run, and zero counts would not prove GECC is enabled. Current RAS code formats the XFX host log's `hardware ability[101] ras_mask[101]` as hex; if the host kernel retained that code, the mask is `0x101` (UMC+DF), still not GECC state or correction evidence. No RAS counters were read.
- **Edit assessment:** No four-area VBIOS edit target is established. PPLib/SMU policy selection, runtime driver gates, UMC metadata, PSP GECC boot configuration and silicon topology are distinct layers. The next useful evidence is exact-card runtime telemetry and source/firmware matching; AMD SMI setter APIs offer optional clock/V/F controls where supported but establish no persistent ROM edit target. Changing opaque SMC/DPM, GFX or FirmwareInfo fields remains unsupported.

The source and pass record is maintained in [chapter 11](../../../docs/11_Sources_and_Research_Gaps.md) and the structured [`targeted_four_area_research` JSON object](ASUS_ROM_ANALYSIS.json). The latest source baseline includes the exact UMC v4.0 width decoder, AMD SMI SCLK/MCLK and V/F setters, the Linux internal `INIT_BY_VBIOS` RAS probe-time PSP path, and the detailed #6101 progressive fan report, distinct SMU 14.0.0/14.0.2 interface and voltage-telemetry paths, AS07 fan report, generic runtime fan/V/F controls, the migrated #9228 process-start report, the newer #9299 SMU/MES host-freeze report, the external next-boot GECC message, AMD SMI's separate RAS-block status/schema queries, Linux's block-level RAS debugfs controls, and the API limitation that AMD SMI's ECC-state and RAS-block-status calls are unsupported in VM guests. After those leads were added, two distinct clean source sweeps rechecked each area against exact local bytes and unresolved questions. The sweeps covered SMU14 PPLib/PMFW source selection, OverDrive/power gating, AMD SMI clock/V/F APIs, ATOM UMC/vram revisions and ECC parser semantics, null ASUS timing/voltage pointers, and RAS/PSP boot paths. No new verifiable lead emerged. All four areas are now at `2/2`; the exact ASUS runtime path, opaque table semantics, and physical-board behavior remain unresolved.

## Boundaries and required follow-up

- Identify and photograph an exact ASUS TURBO R9700 SKU, PCB revision, flash device, DRAM and power circuitry before associating either payload with a card.
- Obtain repeatable software reads and full-chip SPI backups; demonstrate recovery independently of GPU initialization before any experimental write.
- Compare same-board stock and ASUS-updated images. Confirm the fan-table hypothesis by mapping an authoritative revision and correlating table changes with measured fan behavior.
- Establish host-flasher restrictions separately from GPU/PSP/SMU, UEFI and driver checks. The present files do not establish cryptographic authentication or a legitimate custom-signing route.
- Run baseline and post-change performance, power, acoustic, thermal, display, memory-correctness and rollback tests only after the recovery and authentication gates pass.

No updater was run; no firmware was written; no physical ASUS card, recovery image or test result was supplied. This analysis is structural and does not establish flash acceptance, bootability, safety, or performance benefit.

## Sources and tool provenance

- AMD ATOM structures and driver behavior were checked against pinned Linux commit [`32c52ec87d62`](https://github.com/torvalds/linux/blob/32c52ec87d6245ee2d12ed5dd509e40062939b50/drivers/gpu/drm/amd/include/atomfirmware.h) and the [current upstream ATOM header](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/include/atomfirmware.h) plus [driver parser](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/amdgpu_atomfirmware.c). Targeted symbol checks found no exact GFX_INFO v3.1 or SMC/DPM v6.0 body definition in the inspected snapshots; this is not an exhaustive review of vendor-private sources or every branch.
- [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) documents PE headers and certificate records; its prose about post-section data conflicts with its [linked Authenticode PE Signature Format procedure](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx). The calculated candidate SHA-256 follows step 14, including the bounded extra-data range; OpenSSL verifies the PKCS#7 signer signature and matching signed SPC digest. Certificate-chain trust, timestamps and Windows policy were not evaluated. See the [OpenSSL smime documentation](https://docs.openssl.org/3.6/man1/openssl-smime/).
- The [UEFI 2.10 PCI bus specification](https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html) and [compression specification](https://uefi.org/specs/UEFI/2.10_A/19_Protocols_Compression_Algorithm_Specification.html) supply option-ROM boundaries and compression-envelope rules.
- [EDK II TianoCompress source/tests](https://github.com/tianocore/edk2/tree/c1415771ac592ad8509351c46cd3cda4f38d7d52/BaseTools/Source/C/TianoCompress) at commit `c1415771ac592ad8509351c46cd3cda4f38d7d52`: `TianoCompress Version 0.1 Developer Build based on Revision: Unknown`, rebuilt executable SHA-256 `15a086fc0f7d8fed23d6fc62d73039d0c3007d21d5b035dd857c349f9ac96de5`. This executable was rebuilt from the pinned EDK II source commit. The earlier recorded binary was absent, so byte-for-byte restoration cannot be asserted; the decompressed GOP output hash was reproduced.
- [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), release archive SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`; Java runtime `Eclipse Temurin JDK 21.0.12.1+1`, archive SHA-256 `ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94`. Helper: `tools/ghidra_efi_summary.java`.
- GNU `file`, `objdump`, `readelf`, and `strings` static probes, Python version, exact executable versions and hashes are recorded in the accompanying JSON `source_provenance.analysis_tools` object.
