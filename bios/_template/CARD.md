# Physical GPU record — template


Status: unfilled template. This file does not document a real card. Replace placeholders only after copying `_template/` for one physical card. Separate inherited specifications from observations; cite evidence for each populated field. Use `unknown` where unresolved.

## Identity


| Field | Value / evidence |
|---|---|
| Card ID (matches folder and CSV) | TODO |
| Board family (R9700; R9700S separately) | TODO |
| Vendor / exact model / SKU / package code | TODO |
| PCB revision / silkscreen / hardware revision | TODO |
| Serial reference / batch or serial range | TODO |
| Intake date / operator / acquisition provenance | TODO |
| PCI BDF / slot | TODO |
| PCI vendor / device ID | TODO |
| PCI subsystem vendor / device ID | TODO |
| PCI revision register / observed silicon marking | TODO |
| Label, front and back photo paths | TODO |

## Memory, power and cooling


| Field | Value / evidence |
|---|---|
| Reported capacity / bus / effective data rate | TODO |
| DRAM manufacturer / complete part markings | TODO |
| Package count / placement / density / width / speed bin | TODO |
| Memory voltage / datasheet reference | TODO |
| GPU VRM controller / power-stage markings and ratings | TODO |
| GPU / SoC / memory phase topology; memory controller | TODO |
| Shunts / telemetry / overcurrent limits | TODO |
| Power connector / PSU / cable / thermal margin | TODO |
| Cooler / fan controller / fan connector and tach/PWM map | TODO |
| Display connector layout / routing evidence | TODO |

## Flash and recovery


| Field | Value / evidence |
|---|---|
| SPI manufacturer / full marking and suffix / package | TODO |
| PCB reference designator / location / pin-1 photo | TODO |
| Exact datasheet / VCC and I/O requirements | TODO |
| Measured programmer rail and logic levels | TODO |
| JEDEC ID / physical capacity in bytes | TODO |
| Write-protect state / dual-BIOS evidence | TODO |
| Programmer / adapter / clip or socket / software versions | TODO |
| Repeat-read group / comparison logs | TODO |
| Software stock dump path / SHA-256 / bytes | TODO |
| Full SPI stock image path / SHA-256 / bytes | TODO |
| Separate recovery copy location / verification date | TODO |
| Recovery demonstration / stock retest experiment | TODO — not demonstrated |

## Stock baseline and software


Record VBIOS version/part number/build date, PMFW, OS/kernel, drivers, runtime controls, stock and sustained clocks, power limits, temperatures, fan behavior, PCIe link, output tests and reproducible benchmarks. Link experiment and raw-log paths. No baseline measured yet.

## Compatibility, unknowns and history


Record differences from other cards, conflicting reports, unresolved memory/flash/VRM details and every firmware acquisition/write/rollback. A matching version, cooler or GPU die does not establish ROM compatibility. No writes or tests recorded yet.
