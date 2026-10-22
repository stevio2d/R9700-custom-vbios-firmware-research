# ASUS R9700 vendor package acquisition

## Package source and integrity

- Support page: [ASUS TURBO R9700 BIOS support](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G)
- Direct ASUS CDN URL: `https://dlcdnets.asus.com/pub/ASUS/Graphic%20Card/AMD/TURBO-AI-PRO-R9700-32G/AI-PRO-R9700.zip`
- Acquired: 2026-10-18, using `curl 8.18.0` from the official support-page download path.
- Vendor listing: BIOS Update Tool v1, dated 2026-06-04; `AI-PRO-R9700.zip`; 12,582,014 bytes; published SHA-256 `CD499DBF1079B2E65666FF66877C367B4823BBE15910446AB1A2A72C7224B0A0`.
- Local file: [AI-PRO-R9700.zip](AI-PRO-R9700.zip), 12,582,014 bytes; measured SHA-256 `cd499dbf1079b2e65666ff66877c367b4823bbe15910446ab1a2a72c7224b0a0`. Size and digest match ASUS's listing.
- The download response was HTTP 200 with `Content-Type: application/zip` and `Content-Length: 12582014`.

## Static archive inspection and payload extraction

The ZIP contains two Windows PE32+ self-extracting updater files. Their measured hashes were rechecked during the static analysis pass:

| ZIP member | Bytes | SHA-256 |
|---|---:|---|
| `AI-PRO-R9700_default.exe` | 6,489,904 | `79cee792a0a73dfe0a7bc884256046b54cbd7aa6cfbffefbf88ee98da37a9dc2` |
| `AI-PRO-R9700_update.exe` | 6,519,056 | `4daa72acffe1d72353fe117ffe9ddad7a463b848f34b585fcb7cd45f3937ee4f` |

Static listing identified an inner RAR5 archive in each executable. The `BIOS/` directory holds two 2,031,872-byte `.rom` members. Both executable variants contain byte-identical copies of each payload. The copies are preserved once under `payloads/`:

| Extracted payload | Bytes | SHA-256 |
|---|---:|---|
| [7551OG.23.8.0.68.AS04.rom](payloads/7551OG.23.8.0.68.AS04.rom) | 2,031,872 | `0242ce25f406d61f7ff87c3e7be1324ad8f6e1066a2279e6b9ec03b736e60235` |
| [7551OG.23.8.0.68.AS07.rom](payloads/7551OG.23.8.0.68.AS07.rom) | 2,031,872 | `bee92e0a7092c9849b636bf0ec9eaf172c213cb3e34056bac40bc67c6150ecb4` |

Extraction used `bsdtar` / libarchive 3.8.5 to read the named members from `AI-PRO-R9700_update.exe`; the same member hashes were confirmed in `AI-PRO-R9700_default.exe`. 7-Zip 26.00 could list the nested archives but reported `Unsupported Method` when asked to extract those RAR5 members. The outer ZIP and both updater executables were never executed. The payloads are vendor-supplied ROM files, not identified full-chip SPI images, and are not associated with a physical card.

A further static inspection on 2026-10-19 parsed the two embedded PE headers as AMD64 PE32+ GUI self-extractors, found an embedded RAR5 signature at offset `0x6b600` in both, and found bounded `WIN_CERTIFICATE` records. For each updater, the linked Microsoft Authenticode PE step 14 hash calculation covers the pre-certificate overlay containing the RAR5 marker. OpenSSL's PKCS#7 verification succeeds and the SHA-256 in the signed SPC indirect data matches the separately calculated PE image digest. The local SPC parser bounds-checks the enclosing DER sequences, PE-image data OID and SHA-256 DigestInfo; it does not decode or validate the optional `SpcPeImageData` value. The signature check skips certificate-chain validation with `-noverify`; certificate identity/trust, timestamp and Windows policy are not established. It does not establish updater behavior or GPU-side VBIOS authentication/acceptance. A read-only `bsdtar -tf` listing of each SFX archive named the same driver/utility set (`amdvbflash.exe`, `ASUSGraphicVBFlashTool.exe`, driver install/uninstall tools), two ROM members, and `ManualSetting/` and `tools_driver/` files. No updater, flasher, driver installer, or nested executable was launched. The RAR member list is structural evidence only and does not show which payload the tool selects or how it programs a card.

The inventory records each payload's parent as the measured outer ZIP SHA-256. Its extraction details retain the nested executable/member path and intermediate executable hash.

## Read-only structure report

The working-tree [ROM triage reporter](../../../tools/rom_triage.py) read each payload without changing it. For each file it found four bounded PCIR images at offsets `0x40000`, `0x4e600`, `0x120000` and `0x12e600`, plus 38 ATOM header/master/data-table records. The two code-type-0 images had valid 8-bit byte-sum checksums; the code-type-3 images were reported without applying a legacy checksum verdict. No structural warnings were emitted. The extended [read-only ASUS analysis tool](../../../tools/asus_rom_analysis.py) also compares the payloads, decodes the supported ATOM FirmwareInfo v3.5 fields, parses bounded EFI option-ROM headers and emits a byte-range account. The human report and structured output are [ASUS_ROM_ANALYSIS.md](ASUS_ROM_ANALYSIS.md) and [ASUS_ROM_ANALYSIS.json](ASUS_ROM_ANALYSIS.json).

These findings describe only the bytes in the extracted files. They do not establish card association, full-chip coverage, GPU-side VBIOS authentication, boot acceptance, or compatibility with any physical R9700.

## Static executable analysis and reproducibility

The code-type-0 legacy images were extracted by their bounded PCIR lengths and analyzed in Ghidra 12.1.4 as `x86:LE:16:Real Mode`. Each image starts at offset `0x3` with `E9 FA 5F`, a near jump to offset `0x6000`. The Ghidra sidecars retain every recovered function body range, direct-call edge, entry-reachable direct-call path, indirect call and software interrupt; function-body ranges are treated as static code candidates, not proof that every reported instruction executes. Bytes without a recovered function body remain explicitly unresolved because they may include data, unrecognized code or disassembly gaps. See [AS04 legacy Ghidra inventory](analysis/AS04-legacy-ghidra.json), [AS07 legacy Ghidra inventory](analysis/AS07-legacy-ghidra.json), the [human analysis report](ASUS_ROM_ANALYSIS.md) and the [structured analysis record](ASUS_ROM_ANALYSIS.json).

The bounded compressed GOP stream was decompressed with EDK II TianoCompress built from source commit `c1415771ac592ad8509351c46cd3cda4f38d7d52`. The rebuilt executable SHA-256 is `15a086fc0f7d8fed23d6fc62d73039d0c3007d21d5b035dd857c349f9ac96de5`; its output matches the previously recorded 100,560-byte GOP SHA-256 `77779f1c9dd1536338c6d204f82fab865abd8471183e2470942417d25346432b`. The earlier recorded TianoCompress executable hash was `9d07afc9ff531e9dd901bf03073ee8838d26f8bcbbaea273bdae16e8274a6318`, but that binary was not present to re-hash or compare. The new record therefore identifies the rebuilt executable by its actual hash and does not claim byte-for-byte restoration of the absent binary. Ghidra 12.1.4 and Eclipse Temurin JDK 21.0.12.1+1 archives are pinned and hash checked by the restore script.

Reproduce bounded extraction, GOP decompression, static Ghidra analysis, signature checks, region accounting and both reports from the repository root with:

```sh
bash tools/analyze_asus_static.sh
```

The script verifies pinned Ghidra and JDK archive hashes, freshly unpacks those tools into ignored `.cache/`, requires the pinned EDK II source tree to have no tracked modifications, clears its generated C object files and rebuilds TianoCompress. It writes Ghidra projects and temporary inputs under ignored `tools/static-analysis-work/` and `.cache/`, then regenerates the two legacy sidecars and analysis reports. The outputs are static analysis records; the input ZIP and ROM files remain unchanged. No updater, firmware, or hardware is executed or modified.
