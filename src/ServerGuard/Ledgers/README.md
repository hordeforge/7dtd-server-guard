# Ledgers

Per-player bounded state machines and double-entry ledgers: `MovementLedger`,
`CombatLedger`, `InventoryLedger`, `WorldActionLedger`. All main-thread. The inventory
ledger owns the cause-token model and reconciliation ([docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md)
-> Ledger design details).
