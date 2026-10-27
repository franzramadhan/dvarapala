# NNNN: Title

| Status | Date | PR | Release |
|---|---|---|---|
| draft, accepted, implemented or rejected | YYYY-MM-DD | #N | vX.Y.Z |

> One or two sentences: what changes and why.

## Problem

What is wrong or missing, for whom, with numbers if there are any (attack
type, request rate, packet rate, resource budget).

## Proposal

What changes, in a few bullets. Behavior visible to operators first.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/<name>/src/<module>.rs` | What it owns |

### Configuration

| Key | Default | |
|---|---|---|
| `name` | `value` | What it does, how to turn it off |

### Logs and metrics

| | |
|---|---|
| `msg=...` or `metric_name` | What it tells you |

## Test cases

Written and agreed before the implementation. The first implementation
commit adds these as failing tests.

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | ... | ... | ... | unit, integration, fuzz or bench |

## Alternatives

| Option | Why not |
|---|---|
| ... | ... |

## Security and resource limits

What an attacker controls here, the worst case on memory and CPU, and how
it is bounded.

## Rollout

- **Rollout:** version, defaults, anything to do on upgrade.
- **Off switch:** how to turn it off or roll back.
