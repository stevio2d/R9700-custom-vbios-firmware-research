# Goal and success criteria


Establish whether a recoverable custom VBIOS is feasible for one exact AMD Radeon AI PRO R9700 SKU and PCB revision. If feasible, develop and validate an image that delivers a measurable performance, efficiency, thermal, acoustic or specific functional benefit.

The current deliverable is a research repository. No custom firmware success has been demonstrated here. R9700S comparison material does not establish R9700 compatibility.

## Feasibility gates


1. Identify the physical board, memory population, flash device and electrical requirements.
2. Preserve repeatable software dumps and full physical SPI backups with provenance and hashes.
3. Demonstrate a recovery path that works without relying on the candidate firmware or the GPU initializing.
4. Map the candidate field and relevant integrity/authentication boundaries; distinguish flasher restrictions from on-card and driver checks.
5. Identify a credible accepted-image route. If enforced signatures cover the desired change and no legitimate signing route exists, document the limitation and pursue supported runtime controls or vendor firmware.

## Definition of a successful custom VBIOS


All of the following must be evidenced for the exact board and image hash:

- Repeatable AC-off cold boots and warm restarts, with correct PCI enumeration.
- Driver initialization on the declared Windows 11 and Linux x86-64 test configurations; any scope exception is explicit and cannot imply a pass on an untested OS.
- Preserved memory capacity, display outputs, compute, fan control, power behavior and available telemetry.
- Stable graphics, sustained compute, memory-correctness workloads and state transitions, without new resets or relevant errors.
- A repeatable benefit against a stock baseline using the same workload and environment, with acceptable thermal and power margins.
- Demonstrated restoration of the exact stock image, stock retesting, and candidate reinstallation/revalidation.
- Complete board, image, change and test records sufficient for another operator to reproduce the result.

A flasher accepting a file, a successful warm boot, or a faster benchmark alone does not meet these criteria. No universal image or cross-vendor compatibility is assumed. See the [roadmap](docs/07_Custom_VBIOS_Engineering_Roadmap.md), [security gates](docs/06_Firmware_Security_and_Protections.md) and [test plan](docs/10_Laboratory_Test_Plan.md).
