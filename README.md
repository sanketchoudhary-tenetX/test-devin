# test-devin — TenetX Devin Cloud canary

This repo carries **in-repo Devin hooks** so Cognition Cloud sessions that clone
it can talk to TenetX even when Devin account Secrets are not visible to plugin
hook processes.

## What’s in `.devin/`

| File | Role |
| --- | --- |
| `hooks.v1.json` | Registers Pre/PostToolUse (etc.) and **sources** `~/.tenetx/devin.env` before running the hook |
| `tenetx-hook.py` | Bootstrap: unpacks `TENETX_DEVIN_TOKEN` (`txdc1.`) or legacy three-var secrets, downloads the Windsurf guard |

## How to use

1. Mint `TENETX_DEVIN_TOKEN` in TenetX → Install → Cloud environments → Devin.
2. Prefer the **ambient blueprint** so the token exists for hooks (not only Shell):
   paste `docs/tenetx-devin-blueprint-ambient.yaml` into the Devin blueprint for
   this repo, add secret `TENETX_DEVIN_TOKEN`, rebuild snapshot.
3. Start a **new** Devin Cloud session on **this** repo (`main`).
4. Run `pwd`, then check TenetX → Sessions for **Devin Cloud**.

### Backup blueprints

| File | When to use |
| --- | --- |
| `docs/tenetx-devin-blueprint-ambient.yaml` | Persist `TENETX_DEVIN_TOKEN` into `~/.tenetx/devin.env` (fixes hook env isolation) |
| `docs/tenetx-devin-blueprint-setup-token.yaml` | Also runs `tenetx install` with `TENETX_SETUP_TOKEN` so `~/.windsurf` exists for the account plugin |

Settings → Secrets alone is **not** enough for plugin/repo hooks on current Devin
(secrets are bound per Shell tool, not into the hook process).

## Doctor

Inside a session:

```bash
test -f ~/.tenetx/devin.env && echo ambient_ok || echo ambient_missing
tail -n 10 ~/.tenetx/capture_failures.jsonl
```
