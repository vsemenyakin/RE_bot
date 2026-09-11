# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Measures a binary's **resilience to reverse-engineering** and tracks **regressions between versions** — it is *not* a model comparison. An ensemble of LLMs attacks a binary in an isolated sandbox trying to crack its protection (hardcoded constants, proprietary algorithm); a judge model then scores how deeply each protected target was cracked. A target counts as cracked if **any** attacker cracks it. Target binaries are **Raspberry Pi OS (ARM/AArch64)**; the analysis is done on x86 via qemu-user or on a live Pi.

## Commands

```powershell
# Build the sandbox image (first build 15–30 min; runs selftest.sh at the end)
.\build.ps1                       # -Suite bookworm for Pi OS 2023–2024

# Host-side deps (RE tools live in the container, NOT here)
pip install -r requirements.txt

# Full chain: targets_gen -> orchestrate -> judge. Attack config in RE_args.txt.
python run_RE.py                  # or double-click run_RE.cmd on Windows
python run_RE.py --skip-targets   # don't rebuild targets.yaml
python run_RE.py --args other.txt --judge <model>

# Docker-plumbing smoke test — no API keys, spends no money
python tests/smoke_sandbox.py

# Verify link to a live Pi (needs RE_PI_* in .env)
python agent.py --check-pi
```

There is **no unit-test framework or linter**; `tests/smoke_sandbox.py` is the only automated check and it exercises the container plumbing directly.

### Running steps individually

```powershell
# 0. Build targets.yaml deterministically from @re-target-* markers in truth/ (no LLM)
python targets_gen.py --source truth --out truth/protected.yaml --cargo truth/Cargo.toml

# 1. Ensemble attack (truth/ is NOT available to attackers)
python orchestrate.py --sample samples/kerbside `
    --deps samples/libonnxruntime.so samples/vehicle.onnx `
    --models models/claude.txt,models/grok.txt --label kerbside-0.1.0

# 2. Judge scores reports against the source-of-truth
python judge.py --run ens_<date> --targets truth/protected.yaml --source truth

# Single model, single run
python agent.py --sample samples/myapp --model anthropic/claude-opus-4-5
```

Note: `orchestrate.py` no longer takes global budget flags (`--budget-total` in older README examples is gone) — route and budget are per-model in `models/*.txt`.

## Architecture

### Trust boundaries (the core invariant)

Two separate isolations, and the whole measurement collapses if either leaks:

1. **The untrusted binary** runs in a container started with `--network none` — no network, no keys, no host. This is load-bearing for the entire design (see below).
2. **The source-of-truth** (`truth/`: source code + `truth/protected.yaml` answers) is visible **only to the judge** and must never enter an attacker's sandbox — otherwise attackers "crack" the protection by reading the answers. `orchestrate.py` and `agent.py` deliberately have no knowledge of `truth/`; only `judge.py` reads it, and it refuses to run if `--targets`/`--source` live inside `runs/` (from where they'd be mounted into containers).

`samples/` and `truth/` are **gitignored** and placed manually per machine.

### The pipeline

`run_RE.py` chains three independent scripts and picks the run name itself (so the judge finds the report without path-guessing). Attack config is read from `RE_args.txt`; keys are passed through to `orchestrate.py` with `_`→`-` normalization, except `JUDGE_KEYS`/`FLAG_KEYS` which are routed elsewhere.

- **`targets_gen.py`** — deterministic, no LLM. Scans `truth/` for `@re-target-*` markers and emits `protected.yaml`. Target `id` = the name in the code; renaming a protected symbol breaks the regression chain unless `id=` is pinned in the marker.
- **`orchestrate.py`** — runs one `agent.py` subprocess per model, each in its own sandbox, in parallel. A target is cracked if any model gets it. Writes `manifest.json` incrementally so progress survives an abort.
- **`judge.py`** — the only script that sees `truth/`. Scores each target (cracked/partial/not), computes an overall resilience score (1.0 = nothing cracked, 0.0 = all cracked), and a delta vs the previous run of the same version. For **defense** targets the rule is inverted: "revealed" means *bypassed*, not *detected*.

### agent.py — the agentic loop and model factory

The model only emits text; `agent.py` (on the host, with internet + API keys) executes the bash it requests inside the container via `docker exec` and feeds output back. `MAX_OUTPUT_CHARS` truncation and `--max-turns` cap runaway cost — every command's output stays in context forever.

Two **routes**, chosen per model:

- **litellm** — via OpenRouter/LiteLLM API keys, **real money**. Uses a `Sandbox` container. `GenericModel` / `ClaudeModel.run_litellm`.
- **subscription** — `claude -p` run *inside* the container using a Claude Pro OAuth token (`~/.claude/.credentials.json`), spending the Pro window rather than money. `ClaudeModel.run_subscribed`; no `Sandbox` (the `claude -p` container is enough). Only `ClaudeModel` supports it; other models silently fall back to litellm.

`create_model({name, litellm_model, subscription_model, ...})` is the factory (`name=="claude"` → `ClaudeModel`, else `GenericModel`). `main()` is a thin conductor over extracted helpers: `build_parser`, `decide_route`, `preflight_litellm`, `prepare_workdir`, `setup_pi`, `run_subscription_route` / `run_litellm_route`, `write_summary`.

**Attack fingerprint**: `attack_fingerprint()` stamps each run with `profile` + `prompt_sha` + `task_sha` + route-specific fields. The judge only compares runs with the **same fingerprint** — subscription (`subscription-claude`) and litellm (`litellm`) runs are never compared to each other.

### Configuration split

- **`RE_args.txt`** — the session only (sample, deps, model list, label, truth paths).
- **`models/*.txt`** — per model: `name`, `litellm_model` + `litellm_budget`, `subscription_model` + `subscription_budget`, `preferred_run_type`. Symmetric `*_model`/`*_budget` pairs. `preferred_run_type=subscription` without a `subscription_model` silently falls back to litellm; a missing budget for the active route is a hard error.

### The container image (`image/`, tag `re-workbench`)

Ghidra 12.1.3 + PyGhidra, radare2, cross-binutils, `gdb-multiarch`, qemu-user-static with **arm64/armhf rootfs unpacked via `dpkg-deb`** (no ARM binary runs at build time, so host binfmt is not required), plus the `claude` CLI for the subscription route. `/opt/re/bin/` holds the wrappers the model calls (`ghidra-*`, `rpi-info`, `rpi-run`, `re-note`, and `pi-exec`/`pi-push`/`pi-pull` for the live Pi). `/opt/re/TOOLS.md` is injected into the model's prompt.

### Live Raspberry Pi (optional)

Because the container has `--network none`, SSH to a live Pi is done by `agent.py` **from the host** (`PiDevice`); Pi credentials never enter the container. In the litellm route the model gets `pi_push`/`pi_exec`/`pi_pull` tools; in the subscription route it uses the `pi-*` bash wrappers inside the container (which reach the Pi via env vars the host injects). Set `RE_PI_*` in `.env`.

## Gotchas

- **Encodings are contradictory by design.** `build.ps1` must be UTF-8 **with BOM** (Windows PowerShell 5.1 otherwise reads it as cp1251 and the parser dies). Everything under `image/` must be UTF-8 **without BOM and LF-only** — it goes into a Linux container, where a BOM breaks `#!/bin/bash` and CRLF gives `bad interpreter: /bin/bash^M`. If git normalization flips `image/` to CRLF the image builds but the wrappers silently fail. Host Python scripts call `sys.stdout.reconfigure(errors="replace")` because model/binary output crashes cp1251 consoles.
- **`runs/` holds real experiment data**, some of it expensive to reproduce (a subscription run can consume a full Pro window). Never delete or overwrite a run directory without explicit user consent.
- **Model names** are LiteLLM notation; exact OpenRouter strings drift over time (`openrouter.ai/models`).
