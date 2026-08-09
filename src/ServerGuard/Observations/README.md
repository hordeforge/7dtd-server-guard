# Observations

`ObservationAdapter`: copies minimum primitives from a hook into normalized readonly event
structs in pooled ring buffers. Allocation-bounded; never performs IO or unbounded work on
the calling thread.
