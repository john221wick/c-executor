# cpp-executor

Runs untrusted code in isolated environments on Linux. No Docker.

---

## Why

Running code inside Docker has three problems that are hard to work around:

1. **Cold starts.** Every execution spins up a container. That's 200-800ms of overhead before the first line of code runs.

2. **GPU access.** Requires nvidia-container-toolkit, exact driver version pinning, and runtime flags on every container. One version mismatch and nothing works.

3. **Custom libraries.** Want PyTorch or NumPy? You either publish a new image or ship a bloated base with everything pre-installed. No middle ground.

---

## How it works

Each environment is a pre-built root filesystem on disk and a JSON config. No daemon, no image registry.

When code runs, it clones a process into isolated Linux namespaces, mounts an overlay over the rootfs, applies Landlock and seccomp filters, traces every syscall via ptrace, and enforces memory/CPU/PID limits with cgroup v2. The rootfs is read-only and shared. The writable layer is a tmpfs that disappears on exit.

Adding a new environment is one JSON file and one rootfs directory. No code changes.

---

## Setup

```bash
apt install libseccomp-dev libcap-dev

mkdir build && cd build
cmake .. && make -j$(nproc)

mkdir -p /sys/fs/cgroup/executor
mkdir -p /tmp/executor/sandboxes
```

---

## Usage

```bash
./c-executor \
  --env        cpp \
  --source     solution.cpp \
  --input      input.txt \
  --output     expected.txt \
  --in-offsets  0,128,256 \
  --out-offsets 0,64,128 \
  --env-dir    ./environments \
  --threads    4
```

```
Test 0: AC  | 12ms  | 1840KB
Test 1: WA  | 11ms  | 1836KB
  diff: line 3: got "5" expected "6"
Test 2: TLE | 10002ms | 1820KB
```

Exit code 0 if all pass, 1 otherwise.

---

## Adding an environment

```json
{
  "name": "python-ml",
  "rootfs": "/opt/executor/rootfs/python-ml",
  "compile": null,
  "run": ["/usr/bin/python3", "{source}"],
  "extension": ".py",
  "limits": { "memory_mb": 2048, "cpu_time_ms": 30000, "wall_time_ms": 60000, "max_pids": 32 },
  "network": false,
  "gpu": true
}
```

Build the rootfs once, point the JSON at it, done.

```bash
debootstrap --variant=minbase bookworm /opt/executor/rootfs/python-ml
chroot /opt/executor/rootfs/python-ml pip3 install torch numpy
```

---

## Requirements

Linux 5.13+, cgroup v2, x86_64.
