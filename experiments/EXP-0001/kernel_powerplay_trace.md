# EXP-0001 Linux PowerPlay and resume trace

## Evidence checked

- XFX software VBIOS: `bios/xfx-r9700-0000-03-00-0/original/stock-software-read1.rom`, SHA-256 `aad3d6957f284a0cce130f8e106ea7a1118ba9bf1bf86b26d86a28ca11d0bc8d`.
- The [XFX/ASUS comparison](../../bios/xfx-r9700-0000-03-00-0/evidence/XFX_ASUS_COMPARISON.md) places XFX `pplib_pptable_id=0x0000125b` at option-ROM-relative offset `0x23b0`; the bounded raw capture chain also has `0x125b`. ASUS uses `0x1296`. The [custom VBIOS assessment](../../bios/xfx-r9700-0000-03-00-0/evidence/CUSTOM_VBIOS_BENEFIT_ASSESSMENT.md) records the same distinction.
- Host source snapshot: `EXTERNAL_WORKTREE/kernel-build/linux-hwe-7.0-7.0.0`, read over SSH on 2026-10-20. Kernel source-to-installed-module provenance remains unqualified, as noted in [host checks](../../inventory/host_checks.md); this trace does not prove which function path the running device executed.

## Selection path in the inspected source

The host snapshot's `drivers/gpu/drm/amd/include/atomfirmware.h` identifies a nonzero `pplib_pptable_id` as selecting a PowerPlay table supplied by the driver rather than VBIOS. `drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0.c` reads the ATOM FirmwareInfo ID into `smu_table.boot_values.pp_table_id`. Its generic `smu_v14_0_setup_pptable()` then uses an explicit `amdgpu_smu_pptable_id` override when one is configured; otherwise it uses that VBIOS-derived ID. For a nonzero ID on a non-SR-IOV device, that path asks the driver-firmware reader for the matching table. Thus `0x125b` is a key used to choose policy data; it does not encode a clock, voltage or power limit itself.

The same source has an alternate dispatch: `amdgpu_smu.c` selects `smu_v14_0_2_set_ppt_funcs()` for MP1 IP 14.0.2/14.0.3, whose `setup_pptable` callback obtains a combo PowerPlay table from PMFW (`smu_cmn_get_combo_pptable`). The active MP1 IP version and exact setup callback for these four GPUs were not established by this read-only diagnosis. The `0x125b` selection therefore remains a concrete code-path lead, not proof that this specific path is active on this host.

The snapshot's resume routine in `amdgpu_smu.c` attempts `restore_user_od_settings()` when a saved user OD profile is present and prints `Failed to upload customized OD settings` when that callback returns an error. The V14.0.2 upload helper sends `SMU_TABLE_OVERDRIVE` via `smu_cmn_update_table()` and emits `Failed to upload overdrive table!` on failure. This makes the recorded post-resume messages consistent with a failed overdrive-table restoration/upload path in the inspected source. The log does not establish whether a user OD profile was active, identify the lower-level error, or show a performance consequence.

The overdrive restore/upload path is not evidence that the PPLib ID caused the failure. No overdrive control was queried or changed in this experiment, no suspend/resume was performed, and no firmware operation occurred.

## Retained source identity

SHA-256 values from the host source tree:

| File | SHA-256 |
|---|---|
| `drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0.c` | `3da487a1cf2513e1214d8a718be9915dbc5451fd9a8bcd935c86cc15e49e06fe` |
| `drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c` | `5202faaa101fb8f99c70d966e8f1eb345659962e5e5b9ca4fbfdabc67bd0aae3` |
| `drivers/gpu/drm/amd/pm/swsmu/amdgpu_smu.c` | `3cd19d8eba07a0b36edf6ed7a618da1aa6d04bae79a7fede5e0fe52fb4ae1664` |
| `drivers/gpu/drm/amd/pm/swsmu/smu14/smu_v14_0_2_ppt.c` | `5b4bd54212992eb380b5a8b4a3f1522933ae45c2c4a807e8033882587c5fc43b` |
| `drivers/gpu/drm/amd/pm/amdgpu_pm.c` | `536864a60d0fea44cfcfe9c7e07a8c496f5a8d7e4a53dd1c9af9f46995b45aeb` |
| `drivers/gpu/drm/amd/include/atomfirmware.h` | `be8817aba46ed37ad412da72e5cf07d3777c850aa98f0463f85b1db7a8a53c10` |

## Limits

These are source-code observations from the host's build-tree snapshot. The deployed module's complete source/build provenance and the runtime SMU IP dispatch remain unresolved. No matching driver-supplied table entry for `0x125b` was available in the inspected evidence. The ID and resume errors do not establish a firmware defect or a workload bottleneck.
