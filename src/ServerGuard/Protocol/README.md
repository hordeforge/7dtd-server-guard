# Protocol

`ProtocolState`: join/auth/spawn ordering state machine, per-connection and global
cost-weighted token buckets, entity ownership resolution. Network observation only; enqueue
decisions to the main-thread action queue.
