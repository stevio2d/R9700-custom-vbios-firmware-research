# Historical AMDGPU transport contract proposal

No physical kernel interface is implemented or qualified. No driver-extension
fallback is selected. The notes below are general design requirements, not an
implementation plan or authorization for hardware access.

No kernel ABI, module or kernel patch is shipped. `reader.h` is an internal mock
interface; its in-process structs must not become an ioctl ABI by copying them.
The production stub cannot be enabled by a configuration file or CLI flag.

Exact deployed-module provenance, source/patch identity, physical topology,
MP0/firmware identity and controller protocol remain unqualified. A matching
kernel release or module srcversion alone would not establish provenance.

Before implementing a private interface inside that exact AMDGPU tree:

- Define a versioned fixed-width ABI with reserved-zero fields and explicit length,
  per-device root-only permissions and a single active session. Only cached
  capabilities, positive identification and bounded read requests are permitted.
  No register, mailbox, SPI opcode or generic ioctl passthrough is permitted.
- Bind the handle to full BDF, complete PCI identity, device generation, kernel,
  module, firmware and backend build hashes. Cache immutable positively identified
  geometry including every device/bank. A configured ROMSize is insufficient.
- Audit actual controller users and driver lock order. Coordinate runtime PM,
  reset, hot removal and controller ownership with existing locks, rather than
  protecting only the new reader. Determine whether engines need draining from
  evidence. Never use raw-memory or BAR access from userspace.
- Give every transaction and the entire session kernel-owned deadlines. Track
  resources and saved state as initialization proceeds. Cancel and serialize
  cleanup on caller death, inherited/duplicated handles, abandoned sessions,
  reset and removal; final file release alone cannot handle inherited descriptors.
- Restore saved fields only on the same generation under the correct locks.
  A failed restoration poisons access until investigated; do not retry protocols
  or restore stale registers after reset. Record the failure for later callers.
- Positively qualify the exact operation ledger before identification. No program,
  erase, write-enable, protection change, address-mode change or firmware-update
  operation is permitted, including firmware-hidden side effects.

The future state machine is CLOSED → OPENING → IDENTIFYING → IDENTIFIED → READING
→ CLEANING → CLOSED. Every failure/cancellation edge enters CLEANING; device
replacement invalidates saved state, and cleanup failure enters POISONED. Array
reads require IDENTIFIED with complete topology and immutable capacity.

Build any future patch against the exact qualified target sources and run
compiler, static, lock-ordering and fault-injection checks before deployment.
Separate explicit task authorization and documented target, deployment/rollback,
identification and acquisition plans are required before live hardware work. The
existing software-capture command does not authorize those operations.
