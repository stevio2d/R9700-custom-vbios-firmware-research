# AMD Radeon AI PRO R9700 Custom VBIOS Research Report

iturn23image0turn23image1turn23image2turn23image3

**Research cut-off: 18 October 2026**  
**Scope:** Radeon AI PRO **R9700**, not the passive R9700S  
**Target operating systems:** Windows 11 and Linux x86-64  
**Deliverable:** [Download the complete R9700 VBIOS Research Pack](sandbox:/mnt/data/R9700_VBIOS_Research_Pack_2026-10-18.zip)

## Executive assessment

The important conclusion is that the R9700 is a viable firmware-research target, but there is a critical distinction between **being able to write a ROM** and **being able to make an arbitrary modified ROM execute**.

AMD officially specifies the Radeon AI PRO R9700 as an RDNA 4 GPU with 64 compute units, 4096 stream processors, 64 ray accelerators, 128 AI accelerators, 53.9 billion transistors, a 2350 MHz game clock, boost up to 2920 MHz, 32 GB GDDR6 on a 256-bit interface, 640 GB/s peak bandwidth, 64 MB Infinity Cache, PCIe 5.0 x16, 300 W TBP and one 12V-2x6 power connector. AMD also explicitly lists **memory ECC support on Linux only**. citeturn13view0

The PCI device is Navi 48, AMD `1002:7551`. citeturn5search15

There is already direct evidence that R9700 VBIOS is **not identical across brands**. A 2026 ROCm report from a host containing one ASRock and two ASUS R9700s identifies:

| Card | PCI subsystem | VBIOS part number |
|---|---:|---|
| ASRock R9700 | `1849:5413` | `113-APM107573-101` |
| ASUS R9700 | `1043:0626` | `115-G287BP00-100` |
| ASUS R9700 | `1043:0626` | `115-G287BP00-100` |

All three nevertheless reported the same PMFW version, `104.76.0`, which is an especially useful clue: it suggests that vendor-specific VBIOS/board data can differ while at least some underlying AMD power-management firmware remains common. citeturn13view4

That makes cross-vendor binary comparison worthwhile.

The bad news is that I found **no publicly verified workflow demonstrating an arbitrarily hex-edited Radeon AI PRO R9700 VBIOS that cold-boots successfully**. AMD's own AMDVBFlash documentation visibly performs **RSA signature verification** during programming. Community-modified AMDVBFlash builds can reportedly overcome flash-tool restrictions on RDNA 3/RDNA 4, but bypassing the utility's compatibility checks does not demonstrate that Navi 48 will execute modified authenticated firmware. citeturn20view0turn21view0turn13view5

So the project has to solve two independent problems:

**ROM transport**
> Can we read, write, verify and recover the flash reliably?

**ROM authentication**
> Which bytes can be changed without violating an authentication boundary enforced either by AMDVBFlash or by the GPU itself?

The downloadable pack is built around solving those problems experimentally rather than assuming that an RX 6000/7000-era BIOS-edit procedure carries over.

### Confidence key used in the pack

**VERIFIED** means AMD/vendor documentation or particularly strong direct evidence.

**OBSERVED** means first-hand hardware, dump, photograph or operational evidence, but not vendor specification.

**INFERRED** means a technical deduction supported by evidence but not explicitly documented.

**UNKNOWN** is deliberately left unknown rather than filled with a plausible-looking but dangerous guess.

That distinction matters particularly for the SPI flash chip, memory IC part numbers, VRM topology and signature boundaries.

## Vendor, model and VBIOS landscape

I can verify six retail board-partner R9700 products from manufacturer pages or current retail availability, with a seventh manufacturer, Yeston, reported as an AMD partner but without an official R9700 SKU page that I could verify to the same standard.

ASRock officially sells the **Radeon AI PRO R9700 Creator 32GB**, commonly identified as `R9700 CT 32G`. Its specifications are 2350 MHz game, up to 2920 MHz boost, 32 GB GDDR6 at 20 Gbps, 256-bit, four DisplayPort 2.1a outputs, PCIe 5.0 x16, one 12V-2x6 connector and a two-slot form factor. ASRock additionally documents Smart Power Stages/DrMOS, premium power chokes and a 2 oz copper PCB. citeturn24view0

ASUS sells the **Turbo Radeon AI Pro R9700 32GB**, part `TURBO-AI-PRO-R9700-32G`. Particularly interesting for our project, ASUS explicitly says GPU Tweak III can alter **GPU core clock, memory frequency and voltage** and provides advanced fan control. ASUS also says the hardware can support 0 dB fan operation but intentionally disables it in the fan-curve policy for this model. citeturn24view1

Gigabyte sells the **Radeon AI PRO R9700 AI TOP 32G**, `GV-R9700AI-TOP-32GD`, and its official page exposes **both Rev. 1.0 and Rev. 1.1**. That is currently the clearest manufacturer-confirmed evidence of more than one public hardware revision under one R9700 SKU. Gigabyte specifies a turbo blower, vapour chamber/direct GPU contact, all-copper cooling, metal frame and double-ball-bearing fan. citeturn24view2

PowerColor sells the **AI PRO R9700 32G-B**; Australian retail listings currently identify that precise model alongside the other R9700 partner boards. citeturn14search5turn22search7

Sapphire's official product is SKU **`32358-01`**. Sapphire publishes 32 GB 20 Gbps GDDR6, 256-bit bus, 640 GB/s, 2350 MHz game/2920 MHz boost, 300 W, one 12V-2x6, four DP 2.1a outputs and a two-slot blower. Retail package codes such as `32358-01-20G` should **not** be interpreted as PCB revisions without inspecting the actual board. citeturn24view3turn18search11

XFX now sells an R9700 under part **`RX-97XPROAIY`**, with a blower cooler and 2920 MHz boost. citeturn24view4

A Chinese hardware publication that photographed the Sapphire PCB names ASRock, ASUS, Gigabyte, PowerColor, Sapphire, XFX and **Yeston** as partner brands. Because I did not find an equivalent official Yeston product/SKU page during this research, I would classify Yeston as **reported partner, retail board/SKU not independently verified** rather than pretend that its board ID is known. citeturn25view0

Earlier launch-period reporting specifically identified MSI, Biostar, Acer and XFX as missing at the time. XFX subsequently launched the product; I found no equivalent current R9700 product from MSI, Biostar or Acer. citeturn18news35turn24view4

### Current comparison matrix

| Manufacturer/model | PCB/revision evidence | Subsystem ID | Known VBIOS | Core clocks | Memory | TBP | Published voltage | Public BIOS dump status |
|---|---|---:|---|---:|---|---:|---|---|
| ASRock Creator `R9700 CT 32G` | PCB revision not published | `1849:5413` observed | `113-APM107573-101`; version `023.008.000.068.000001` also reported | 2350 / 2920 MHz | 32 GB GDDR6, 20 Gbps, 256-bit | 300 W class | No fixed stock value published | No indexed dump verified in this research |
| ASUS Turbo `TURBO-AI-PRO-R9700-32G` | revision not published | `1043:0626` observed | `115-G287BP00-100` | 2350 / 2920 class | 32 GB GDDR6, 20 Gbps class | 300 W class | Dynamic tuning exposed; no stock fixed value published | No indexed dump verified |
| Gigabyte AI TOP `GV-R9700AI-TOP-32GD` | **Rev. 1.0** | Unknown | Unknown | reference-class / 2920 boost | 32 GB GDDR6 256-bit | 300 W class | Not published | Not verified |
| Gigabyte AI TOP same SKU | **Rev. 1.1** | Unknown | Unknown | reference-class / 2920 boost | 32 GB GDDR6 256-bit | 300 W class | Not published | Not verified |
| PowerColor `AI PRO R9700 32G-B` | Unknown | Unknown | Unknown | 2350 / 2920 class | 32 GB GDDR6, 20 Gbps | 300 W | Not published | Not verified |
| Sapphire `32358-01` | Unknown | Unknown | Unknown | 2350 / 2920 MHz | 32 GB, 20 Gbps, 256-bit | 300 W | Not published | Not verified |
| XFX `RX-97XPROAIY` | Unknown | Unknown | Unknown | reference / 2920 boost | 32 GB GDDR6 | 300 W class | Not published | Not verified |
| Yeston | Reported only | Unknown | Unknown | Unknown | expected R9700 configuration | Unknown | Unknown | Unknown |

ASRock/ASUS board and VBIOS identities come from the ROCm first-hand data; manufacturer clock/memory information comes from the relevant vendor pages. citeturn13view4turn24view0turn24view1turn24view2turn24view3turn24view4

TechPowerUp's VGA BIOS database blocked automated access during this research, and search indexing did not expose an R9700 BIOS record. Accordingly, the table says **not verified**, not “no BIOS exists”. A major first task is building our own properly attributed ROM collection.

## Hardware, PCB, flash and protection findings

### Navi 48 and memory

The official baseline is unusually well suited to large AI workloads: 32 GB on a 256-bit bus at 20 Gbps gives AMD's specified **640 GB/s** bandwidth. The R9700 contains the full advertised 64-CU/4096-SP configuration; consequently, there is currently no evidence that a “shader unlock” comparable to some historical Radeon cards is waiting inside the VBIOS. citeturn13view0

A detailed independent inspection identifies Navi 48 revision C0 and reports Samsung memory on its ASRock sample via GPU-Z. That is useful evidence for the **memory manufacturer on at least one board**, but it does not establish that every R9700 uses Samsung or give us a sufficiently verified physical IC code. citeturn7view1

The Sapphire PCB photograph above is more useful structurally. The visible side shows the Navi 48 package surrounded by GDDR6 packages, with substantial R15-inductor power circuitry on both sides of the GPU. The photographs are high enough quality to understand general PCB topology but not sufficient for me to state a DRAM or SPI top marking with engineering confidence. citeturn25view0

**Therefore the exact GDDR6 part number remains UNKNOWN.**

That is preferable to making the dangerous leap to a plausible Samsung `K4Z...` code and designing timings around the wrong speed bin.

### Shared PCB family

Alphacool's R9700 waterblock is explicitly compatible with **ASRock Creator, ASUS Turbo, PowerColor and Sapphire**, which is useful evidence that these four boards are mechanically very closely related. citeturn10view0

In Alphacool's development discussion, Sapphire and ASRock PCB layouts were described as essentially identical, while ASUS appeared only minimally different. User-supplied PowerColor photographs were also posted; later Gigabyte photographs showed differences including the fan-connector region/board length. citeturn10view1turn11search0

That is encouraging for cross-ROM study but **does not prove electrical interchangeability**. The same waterblock can fit two cards with different PWM controllers, ROM contents, strap resistors, output mappings or current-limit programming.

### VRM

ASRock officially confirms SPS/DrMOS power stages, enhanced chokes and a 2 oz copper PCB but does not disclose the controller or exact number of phases. citeturn24view0

Gigabyte similarly documents the thermal and mechanical construction rather than a complete phase-level schematic. citeturn24view2

For that reason, an “aggressive 350 W VBIOS” should **not** be attempted based solely on apparent similarity to an RX 9070 XT. The specific PWM controller, power-stage ratings, programmed over-current protection and 12V-2x6 connector thermals need to be identified first.

### SPI flash: the most important unresolved item

I could not verify, from an authoritative source or sufficiently legible R9700 PCB close-up:

- the SPI NOR manufacturer;
- exact part number;
- capacity;
- whether its I/O/VCC is 1.8 V or 3.3 V;
- its board reference designator;
- whether every vendor uses the same flash;
- whether Gigabyte Rev. 1.0 and 1.1 use the same device;
- whether the complete physical device contains multiple logical/active ROM regions.

**Do not buy a programmer adapter based on a guessed Winbond/MXIC/GigaDevice part.**

The correct board-intake procedure is:

1. Strip the cooler only after photographing labels and warranty-sensitive areas.
2. Photograph **both PCB sides** under a microscope/macro lens.
3. Locate SOIC-8/WSON-8 flash candidates.
4. Read the complete top marking.
5. Pull the manufacturer's datasheet.
6. Establish pin 1 and the exact VCC range.
7. Check pin 4/GND by continuity.
8. Measure for unexpected powered rails before attaching the programmer.
9. Attempt several **reads only**.
10. Do not write until three complete reads hash identically.

A commonly encountered 8-pin SPI NOR convention is `/CS`, IO1, `/WP`/IO2, GND, IO0, CLK, `/HOLD`/IO3, VCC on pins 1–8 respectively, but the actual R9700 chip's datasheet must override that generic convention.

### VBIOS signature and other protection

AMD's AMDVBFlash documentation gives us an unusually useful clue. The official programming example visibly reports an **RSA signature verification** result before programming. The same guide documents saving, programming, comparing and checksumming VBIOS images. citeturn20view0turn21view0turn21view1

What it does **not** tell us is whether Navi 48's hardware/firmware boot chain independently authenticates:

- the entire ROM;
- only embedded AMD firmware components;
- individual ATOM tables;
- the GOP;
- board-specific tables;
- active and inactive copies separately.

That boundary is what has to be reverse-engineered.

An unofficial modified AMDVBFlash 5.0.879 is reported to support RDNA 3 and RDNA 4 and to expose active/inactive ROM handling. Igor's Lab explicitly warns that the binary is unauthorised and untested and recommends a hardware recovery method. The associated instructions use force switches such as `-fv -fp -fa` and claim RDNA 3+ uses active/inactive mirrored firmware regions. citeturn13view5

I would treat the mirrored-image claim as **community evidence requiring R9700 verification**, not as an AMD specification.

Most importantly:

> **A modified flasher defeating a software write restriction is not equivalent to defeating VBIOS cryptographic authentication.**

That is why I would not begin this project by running the force-flasher.

## Safe flashing and recovery architecture

The AMD-authored guide documents the core syntax:

```text
amdvbflash -i
amdvbflash -ai <adapter>

amdvbflash -s <adapter> <file>
amdvbflash -p <adapter> <file>

amdvbflash -v <adapter> <file>
```

It also provides separate file/BIOS/ROM checksum operations. The document supports Windows, Linux, UEFI and DOS, although it dates from 2020 and therefore should be regarded as a **command reference rather than proof that that particular build supports R9700**. citeturn20view0turn21view0turn21view1

For a real R9700 lab, I would make the backup gate considerably stricter.

### Before the first experimental write

On Windows:

```text
amdvbflash.exe -i
amdvbflash.exe -ai 0

amdvbflash.exe -s 0 stock_A.rom
amdvbflash.exe -s 0 stock_B.rom

amdvbflash.exe -v 0 stock_A.rom

certutil -hashfile stock_A.rom SHA256
certutil -hashfile stock_B.rom SHA256
```

On Linux:

```bash
sudo ./amdvbflash -i
sudo ./amdvbflash -ai 0

sudo ./amdvbflash -s 0 stock_A.rom
sudo ./amdvbflash -s 0 stock_B.rom

sha256sum stock_A.rom stock_B.rom
cmp stock_A.rom stock_B.rom

sudo ./amdvbflash -v 0 stock_A.rom
```

AMD documents the `-s`, `-p` and `-v` operations used here. citeturn20view0turn21view0turn21view1

Then perform an **independent physical-chip backup**. Once the actual SPI part and voltage have been positively identified, a flashrom-capable programmer workflow can look like:

```bash
flashrom -p ch341a_spi -r ext_read_1.bin
flashrom -p ch341a_spi -r ext_read_2.bin
flashrom -p ch341a_spi -r ext_read_3.bin

sha256sum ext_read_*.bin
```

The three hashes must match before you trust the programmer/clip arrangement.

Make the full-chip image immutable:

```bash
cp ext_read_1.bin GOLDEN_FULL_CHIP_IMAGE.bin
sha256sum GOLDEN_FULL_CHIP_IMAGE.bin \
  > GOLDEN_FULL_CHIP_IMAGE.sha256
```

Do **not** assume the software VBIOS dump and physical-chip dump must be the same size. Preserve the entire physical flash for recovery.

### Programmer recommendation

For an expensive R9700, my hierarchy would be:

**Best:** a quality universal programmer that explicitly lists the identified flash IC and supports its voltage/package, plus a suitable socket/adapter.

**Acceptable after verification:** CH341A with a quality clip **only after measuring the programmer rail and determining whether a 1.8 V adapter is required**.

**Most reliable when the bus fights the programmer:** desolder the ROM and program it out of circuit rather than repeatedly forcing an unstable in-circuit write.

A multimeter and microscope are part of the flashing kit, not optional accessories.

### Recovery ladder

If a bad-flashed card still enumerates on PCIe, use an iGPU or second GPU for display, identify the dead card by BDF/subsystem ID and restore the exact original image.

If display output is dead but the R9700 is still present on PCIe, the same approach may work; never assume adapter `0` is the failed card.

If it no longer enumerates, stop software recovery attempts and restore the **full-chip golden image externally**.

If three in-circuit reads cannot be made identical, do not write. Desolder/isolate the flash instead.

After every firmware experiment, use a **complete AC-off cold boot**, not just a warm restart. The community RDNA3/RDNA4 flasher report also recommends full power-downs between operations. citeturn13view5

The pack contains a Mermaid recovery flowchart and a full test-lab checklist.

## What is actually worth modifying

There are useful opportunities, but not all require a VBIOS.

ASUS explicitly exposes core clock, memory frequency and voltage adjustment through GPU Tweak III on its R9700. citeturn24view1

That changes the recommended development order dramatically: **first establish that the hardware benefits from a setting at runtime, then consider encoding it in firmware**.

### Conservative performance profile

The first experiment should keep the card within the stock 300 W envelope.

Start with an undervolt, then test core frequency, then memory frequency. Record GPU edge, junction, memory temperature, fan RPM, board power and application throughput. The R9700's blower cooling and large 32 GB memory population make memory/junction thermals important alongside core temperature. AMD's reference power specification is 300 W. citeturn13view0

Once a stable runtime target has survived long mixed workloads, ask what the VBIOS would add. If supported tuning software already provides persistence, a firmware edit may offer no worthwhile benefit.

The interesting firmware targets are instead likely to be:

- power-limit ceilings;
- fan floor or fan-curve policy;
- limits unavailable to runtime tools;
- persistent headless settings;
- fixes present in a newer signed vendor ROM.

The ASUS page is particularly revealing because it says 0 dB-capable hardware is intentionally prevented from operating that way through policy. citeturn24view1

### Aggressive overclock

Only move beyond 300 W after determining that stock performance is **actually power-limited**.

Before doing so, identify:

- exact VRM controller;
- exact SPS/power-stage parts;
- phase topology;
- memory ICs and their thermal limits;
- SPI recovery hardware;
- 12V-2x6/cable/PSU margin;
- whether the cooler has real thermal headroom.

A signed R9700 donor ROM from a demonstrably compatible board with a higher allowed limit would be preferable to arbitrary table editing. At present, however, all verified vendor specifications I found cluster around the same 300 W reference specification rather than providing an obvious “factory 350 W R9700 BIOS”. citeturn13view0turn24view3

If an arbitrary edit proves bootable, make the **first power change small**. Do not go directly from 300 W to an extreme limit merely because the GPU die resembles an RX 9070-series product.

### Feature unlocking

This is the most speculative scenario.

There is no evidence of disabled compute units waiting to be enabled: AMD already advertises the full **64 CUs / 4096 SP**. citeturn13view0

AMD already lists **ECC support on Linux only**, making a hypothetical Windows ECC unlock more likely to involve the driver/software stack as well as, or instead of, VBIOS policy. citeturn13view0

The best approach is therefore to choose **one particular feature**, then determine where it is gated:

```text
hardware fuse?
      ↓
AMD firmware?
      ↓
board VBIOS / ATOM table?
      ↓
PCI subsystem policy?
      ↓
kernel/driver?
      ↓
user-space software?
```

Do not start by changing PCI device IDs.

A particularly useful experiment would be comparing the known ASRock and ASUS ROMs because they have different subsystem IDs and different VBIOS part numbers but the same reported PMFW 104.76.0. citeturn13view4

That comparison may reveal which regions are vendor board data versus common AMD blobs.

### The single-byte authentication experiment

Once hardware recovery is proven, the most informative custom-ROM test is not an overclock.

It is a **minimal, controlled modification**.

Take the stock ROM, map all image/table/signature boundaries, alter one non-critical candidate field, preserve every unrelated byte, recompute only documented non-cryptographic checksums and attempt to program it.

There are then three outcomes:

1. **Flasher refuses it:** host utility authentication/compatibility is blocking you.
2. **Flasher writes it, card will not initialise:** likely on-card authentication or corrupted required structure.
3. **Card cold-boots and the field's behaviour changes:** you have identified a mutable region and can begin systematic VBIOS engineering.

That experiment is vastly more valuable than attempting a 350 W BIOS first.

### Definition of a genuinely working custom R9700 VBIOS

I would not label a ROM “working” until it passes:

| Test | Required result |
|---|---|
| Complete AC-off boot | Pass repeatedly |
| PCI enumeration | Correct |
| Windows driver initialisation | Pass |
| Linux `amdgpu` initialisation | Pass |
| Display outputs | As expected |
| ROCm/compute | Pass |
| GPU, junction and memory telemetry | Valid |
| Fan control | Valid |
| Power telemetry | Valid |
| Sustained compute | Stable |
| Memory-heavy workload | Error-free |
| Graphics workload | Stable |
| AER/WHEA/GPU-reset/SMU logs | Clean |
| ROM re-read | Matches intended image |
| Stock rollback | Proven |
| Re-flash candidate and revalidate | Proven |

This is especially important because a 2026 ROCm issue documents R9700 fan/SMU behaviour under Linux, including ASRock/ASUS boards using different VBIOSes while sharing PMFW 104.76.0; thermal-control behaviour needs to be part of firmware validation, not an afterthought. citeturn13view4

## Downloadable engineering pack

The complete pack is here:

**[Download R9700_VBIOS_Research_Pack_2026-10-18.zip](sandbox:/mnt/data/R9700_VBIOS_Research_Pack_2026-10-18.zip)**

It contains 18 files and deliberately keeps each topic separate:

| File | Format | Purpose |
|---|---|---|
| `README.md` | Markdown | Scope, evidence rules and central conclusion |
| `00_Executive_Summary.md` | Markdown | Decision-level findings |
| `01_Brands_Models_Board_IDs.md` | Markdown | Vendor, SKU, SSID and revision inventory |
| `02_VBIOS_Comparison.md` | Markdown | Known VBIOS versions, ROM acquisition and diff workflow |
| `03_Hardware_PCB_Memory_VRM.md` | Markdown | Navi 48, memory, VRM, PCB and cooler research |
| `04_SPI_Flash_Hardware.md` | Markdown | SPI identification, pinout methodology and programmer requirements |
| `05_Flashing_Backup_Recovery.md` | Markdown | Windows/Linux flashing and brick recovery |
| `06_Firmware_Protections_Legal.md` | Markdown | RSA/authentication, write protection, warranty/legal considerations |
| `07_Mod_Opportunities.md` | Markdown | Power, voltage, clocks, timing and feature analysis |
| `08_Mod_Plans.md` | Markdown | Conservative OC, aggressive OC and gated-feature workflows |
| `09_Test_Lab_Checklists.md` | Markdown | Intake, backup and validation sheets |
| `10_Sources_and_Image_Links.md` | Markdown | Vendor, VBIOS, PCB/photo and teardown source links |
| `R9700_model_vbios_matrix.csv` | CSV | Machine-readable board/VBIOS research matrix |
| `flashing_recovery.mmd` | Mermaid | Flash/recovery workflow |
| `mod_research_flow.mmd` | Mermaid | VBIOS reverse-engineering workflow |
| `R9700_PCB_reference_map.png` | PNG | Annotated, non-photographic PCB topology map |
| `source_manifest.json` | JSON | Machine-readable source list |
| `MANIFEST.md` | Markdown | SHA-256 hashes of pack contents |

The PCB photographs themselves are not republished in the archive; instead, the pack contains the source and direct image links plus an original annotated reference diagram. The most useful public Sapphire PCB imagery was located in the October 2025 hardware photo set shown above. citeturn25view0

The present blockers are deliberately highlighted rather than guessed: **exact SPI flash chip and voltage per PCB, exact memory IC codes, full VRM controller/power-stage mapping for each revision, ROM dumps from the remaining vendors, and the precise Navi 48 VBIOS authentication boundary**. Those are the measurements that should be completed before attempting a genuinely custom R9700 image.