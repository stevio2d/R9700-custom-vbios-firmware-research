# GPU, Memory and Hardware Specifications


> This chapter separates AMD- and vendor-published specifications checked on 2026-10-18 from inherited N/R1/R2 observations and card-specific unknowns. Published specifications are not measurements of a card in this repository. See the [source index](../sources/README.md) and [research gaps](11_Sources_and_Research_Gaps.md). Supplied originals: [N](../sources/originals/notes.md), [R1](../sources/originals/deep-research-report.md), [R2](../sources/originals/deep-research-report%20%281%29.md).

## AMD-published GPU baseline


AMD's [R9700 product specification page](https://www.amd.com/en/products/graphics/workstations/radeon-ai-pro/ai-9000-series/amd-radeon-ai-pro-r9700.html) was checked on **2026-10-18**. It publishes RDNA 4, 64 compute units, 4096 stream processors, 128 AI accelerators, 64 ray accelerators, 128 ROPs and 53.9 billion transistors.

The same page publishes game clock 2350 MHz and boost up to 2920 MHz; 32 GB GDDR6, 256-bit memory interface, 640 GB/s peak bandwidth and 64 MB Infinity Cache; PCIe 5.0 x16, 300 W TBP, active cooling, double-slot board width, 12V-2x6, and a 750 W minimum PSU recommendation. AMD says memory ECC support is “Yes (Linux Only),” supports up to four partner-configurable display outputs, and lists H.264, H.265/HEVC and AV1 encode/decode.

All six active-board vendors in [chapter 1](01_Vendors_and_Models.md) publish 20 Gbps memory; partner layouts and clocks can vary. These are published product specifications. They do not establish actual board power, sustained clocks, ECC reporting, memory population, sensor behavior or firmware policy on an unidentified card.

## Memory chips: what remains unestablished


The published 32GB capacity and 256-bit interface do not
identify the exact memory package arrangement.

AMD SMI `27.1.0+7da43026` reports Samsung GDDR6 on four functions identified by the same tool as Radeon AI PRO R9700 on `capture-host` (see the [host check record](../inventory/host_checks.md)). This is software-reported memory-vendor information, not inspection of the soldered DRAM markings; it does not establish package part number, count, population or a universal R9700 BOM.

Still required:

- DRAM manufacturer: Samsung, SK hynix, Micron or another supplier.
- Exact memory part number.
- Number of packages.
- Density and package width.
- Physical placement.
- Memory rail voltage.
- Supported timing and speed bins.
- Whether different board revisions use different DRAM.

Do not assume every R9700 has identical memory chips.

## GPU die


AMD's checked page specifies the RDNA 4 architecture but does not name a die identifier. N/R1/R2 report Navi 48, and R1 reports revision C0 on one ASRock inspection sample; those sample claims remain inherited. R2 leaves stepping unresolved. Record the actual PCI revision and silicon marking where visible rather than assigning that sample’s stepping to every card.

## Power delivery


Unknown per board:

- VRM controller.
- GPU power-stage count and current rating.
- Memory VRM design.
- Shunt values and telemetry configuration.
- Hardware overcurrent limits.
- PCB trace and connector thermal margins.

These must be inspected before proposing a higher power limit.

## Why these details matter


Memory vendor and VRM differences can make cross-flashing unsafe.

Even when two cards use the same GPU, a mismatched ROM could
configure the wrong fan, memory or voltage behavior.

## Additional evidence leads from the reports


R1 reports Samsung memory identified through GPU-Z on one ASRock sample. The linked [Igor's LAB review](https://www.igorslab.de/en/amd-radeon-ai-r9700-alias-rx-9070xt-in-the-big-workstation-graphics-card-test-what-are-the-benefits-of-double-the-memory-at-work/) also describes an ASRock sample as Navi 48 C0 with Samsung GDDR6. This remains an external reviewer's software-reported sample detail, not a physical DRAM part number or universal BOM. That article's table gives 22.0 Gbps / 704 GB/s, while its prose gives 644.6 GB/s; all six vendor product pages publish 20 Gbps, and AMD publishes 640 GB/s. Preserve the discrepancy rather than treating the review's table as a verified R9700 memory rate. Do not invent a Samsung `K4Z...` code or import RX 9070 memory straps. Capacity and bus width do not establish package count, density or training requirements.

R1 describes Sapphire PCB photographs showing memory surrounding the GPU and R15-marked inductors, but says markings are insufficiently legible for exact DRAM/SPI identification. R2 cites older Alphacool discussion lacking board information; R1 cites later waterblock compatibility covering ASRock, ASUS, PowerColor and Sapphire, with reported Gigabyte layout differences. Keep the dates and source contexts separate. Mechanical fit and visible similarity cannot establish identical VRMs, GPIOs, memory, firmware or electrical compatibility.

ASRock's SPS/DrMOS, choke and copper-PCB marketing and Gigabyte's cooler descriptions are inherited source claims. Neither supplies a verified controller, stage rating or phase map. Record GPU, SoC and memory rails separately; inductor counts alone do not prove phase topology. Inspect shunts, current telemetry, OCP and connector/cooler margins before any power proposal.

The inherited peak-bandwidth calculation is `20 Gbit/s × 256 / 8 = 640 GB/s`; it does not predict sustained application throughput. Likewise, up-to boost clocks are not guaranteed sustained clocks. Record actual stock behavior and absent sensors in the [card record](../bios/_template/CARD.md) and [test plan](10_Laboratory_Test_Plan.md).
