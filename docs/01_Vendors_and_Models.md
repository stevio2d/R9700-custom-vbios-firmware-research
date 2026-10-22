# R9700 vendors, models and PCB revisions


> This chapter separates vendor-published specifications checked on 2026-10-18 from inherited N/R1/R2 reports and card-specific unknowns. Public specifications are not measurements of a card in this repository. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## Vendor-published active R9700 models


The official product and support pages linked here were checked on **2026-10-18**. Specifications are what each vendor publishes; they do not establish the BOM, firmware contents, or behavior of an unidentified physical board. The update column records what the checked vendor page exposed on that date. “No VBIOS item shown” is not proof that no package exists elsewhere.

| Active board / published model identifier | Vendor-published distinguishing details | Official product and support pages; update evidence checked 2026-10-18 |
|---|---|---|
| ASUS Turbo `TURBO-AI-PRO-R9700-32G` | 32 GB GDDR6, 20 Gbps, 256-bit; default game/boost 2350/2920 MHz; GPU Tweak III OC mode up to 2370/2940 MHz; 3× DP 2.1a + HDMI 2.1b; 2-slot; 12V-2x6 | [Tech specs](https://www.asus.com/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/techspec/). [BIOS support page](https://www.asus.com/us/motherboards-components/graphics-cards/turbo/turbo-ai-pro-r9700-32g/helpdesk_bios/?model2Name=TURBO-AI-PRO-R9700-32G) lists BIOS Update Tool v1, dated 2026-06-04, for fan-curve refinement. Its ZIP was acquired and its measured size/hash match the published metadata; two ROM payloads were statically extracted. Neither is associated with a physical card. See [chapter 3](03_VBIOS_Collection_and_Diff.md) and the [acquisition record](../bios/vendor-packages/asus/ACQUISITION.md). |
| ASRock Creator `R9700 CT 32G` / Radeon AI PRO R9700 Creator 32GB | 32 GB GDDR6, 20 Gbps, 256-bit; 2350/2920 MHz; 4× DP 2.1a; blower, vapour chamber; 2-slot; 12V-2x6 | [Product/support page](https://www.asrock.com/Graphics-Card/AMD/Radeon%20AI%20PRO%20R9700%20Creator%2032GB/) lists the model and a quick-installation guide; no VBIOS file or version was shown on the checked page. |
| Gigabyte AI TOP `GV-R9700AI-TOP-32GD`, Rev. 1.0 | 32 GB GDDR6, 20 Gbps, 256-bit; 2350/2920 MHz; 3× DP 2.1a + HDMI 2.1b; 2-slot | [Rev. 1.0 product](https://www.gigabyte.com/Graphics-Card/GV-R9700AI-TOP-32GD-rev-10/sp) and [support](https://www.gigabyte.com/jp/Graphics-Card/GV-R9700AI-TOP-32GD-rev-10/support) pages. The support page has a BIOS heading and generic same-series update guidance, but no VBIOS file/version row. |
| Gigabyte AI TOP `GV-R9700AI-TOP-32GD`, Rev. 1.1 | Same published core and memory configuration as Rev. 1.0; 3× DP 2.1a + HDMI 2.1b; 2-slot | [Rev. 1.1 product](https://www.gigabyte.com/au/Graphics-Card/GV-R9700AI-TOP-32GD-rev-11/sp) and [support](https://www.gigabyte.com/au/Graphics-Card/GV-R9700AI-TOP-32GD-rev-11/support) pages were checked separately. The support page has a BIOS heading and generic same-series update guidance, but no VBIOS file/version row. The public revision labels do not prove identical PCBs or ROMs. |
| PowerColor `AI PRO R9700 32G-B` | 32 GB GDDR6, 20 Gbps, 256-bit; 2350/2920 MHz; 4× DP 2.1a; 2-slot; 12V-2x6 | [Product/download page](https://www.powercolor.com/product-detail258.htm) lists the SKU and specifications. Its download area exposed a driver and manual, but no VBIOS file/version. |
| Sapphire `32358-01` | 32 GB GDDR6, 20 Gbps, 256-bit; 2350/2920 MHz; 640 GB/s; 4× DP 2.1a; active blower; 2-slot; 300 W; 12V-2x6 | [Product page](https://www.sapphiretech.com/en/commercial/radeon-ai-pro-r9700) identifies SKU `32358-01`; no public VBIOS package/version was shown in the checked product content. `32358-01-20G` is not established as a PCB revision. |
| XFX `RX-97XPROAIY` | 32 GB GDDR6, 20 Gbps, 256-bit; 1620 MHz base, 2350 MHz game, 2920 MHz boost; 4× DP 2.1a; blower; 2-slot; 12V-2x6 | [Product/support page](https://helpdesk.xfxforce.com/shop/xfx-amd-radeon-ai-pro-r9700-32gb-gddr6-4xdp-amd-rdna-tm-4) identifies the SKU, but its metadata labels the product name “Radeon AI Pro R9070” while the title and description say R9700. No VBIOS package/version was visible on the checked page. |

ASRock's board is confirmed by its own product page. AMD's [partner page](https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro.html) categorizes ASRock under server partners and lists ASUS, Gigabyte, PowerColor, Sapphire and XFX under AIB partners. R1's **Yeston** partnership lead still has no verified official R9700 SKU page. Historical “not found” statements about MSI, Biostar and Acer are not current availability claims. R2's AMD engineering/non-resale sample does not establish a retail reference board.

R1 reports ASRock subsystem `1849:5413` / VBIOS part `113-APM107573-101` and ASUS subsystem `1043:0626` / part `115-G287BP00-100`. A public [ROCm issue thread](https://github.com/ROCm/legacy-rocm-build/issues/6101) contains contributor logs with these same subsystem and VBIOS strings, which corroborates the external report but is not vendor product data or a local observation. The checked product pages do not establish the PCI IDs, PCB markings, ROM hashes, flash components or VRM BOM of any card.

## Separate comparison family: R9700S


N/R2 identify Sapphire passive `32361-01`; R2 additionally identifies ASRock `R9700S PS 32G` and a PowerColor R9700S. R2 describes the ASRock as 190 × 112 × 38 mm, passive vapour-chamber cooling with PTM7950, and Sapphire as a four-DP passive model. These details are inherited and unverified here. **Do not treat an R9700S ROM as a donor or recovery image for an active R9700.** Cooling, thermal policy, fan wiring and board implementation require separate records and validation.

## Physical-card intake


Create one [CARD.md](../bios/_template/CARD.md) and [cards.csv](../inventory/cards.csv) row per physical card, even for identical SKUs. Record:

- Vendor, model, complete SKU, PCB silkscreen/revision and serial/batch reference.
- PCI vendor/device, subsystem IDs, PCI revision and BDF/slot mapping.
- VBIOS version, part/build/date, stock software and full-SPI hashes.
- SPI marking, package, JEDEC ID, capacity, voltage and physical location.
- DRAM markings/population; VRM controller, stages and phase topology.
- Output layout, cooling, fan/tach/PWM configuration, stock clocks/power and temperatures.

N calls vendor ROM differences unknown; R1 reports differing ASRock/ASUS IDs/part numbers; R2 suggests a common AMD version baseline. These can coexist, but **none establishes byte-level identity or interchangeability**. Obtain actual images before concluding which regions differ. See [collection](03_VBIOS_Collection_and_Diff.md) and [unresolved evidence](11_Sources_and_Research_Gaps.md).
