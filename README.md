# sched-forensics v1.0.0

Read-only Linux scheduler forensics CLI, Python 3 standard library only. GPLv3.

## Usage

```bash
python3 main.py --interval 2 --count 10 --extended --color always
python3 main.py --interval 1 --count 5 --json --report report.json
python3 main.py --interval 2 --snapshot after.json
python3 main.py --compare before.json after.json --json --pretty
python3 main.py --pid 1 --extended --topology --kernel
python3 main.py --interval 2 --continuous --csv threads.csv
```

`--snapshot` saves the last raw collection. To compare snapshots, capture `before.json` and `after.json` in separate invocations. `--compare` requires snapshots from the same host and boot unless override flags are used.

## Measurements

- Per-thread CPU time and runnable wait deltas from `/proc/PID/task/TID/schedstat`, when available
- Fallback CPU utilization from `/proc/PID/task/TID/stat`
- Voluntary and involuntary context switch rates
- CPU placement changes, optional scheduler migration counters
- Per-core CPU utilization and system pressure stall information
- Optional scheduling details, CPU affinity, cgroup membership, topology, and kernel scheduler tunables
- Read-only heuristics for CPU saturation, runqueue waiting, migration churn, context switching and CPU pressure
- JSON and CSV reports, raw snapshots, comparison, and Cosmos terminal view

## Caveats

Linux-only. Scheduler accounting availability depends on kernel configuration, permissions and kernel version. `schedstat` and `/proc/PID/task/TID/sched` may be restricted or incomplete. CPU placement changes between samples do not prove every intermediate migration. Runqueue wait counters may be disabled. Thread lifetime is matched by PID, TID and start ticks. CPU percentages are relative to one logical processor, not total machine capacity. Snapshot comparisons across reboots are not meaningful. This program does not change scheduler policies or process priorities.

## License

GNU General Public License version 3.# sched-forensics
