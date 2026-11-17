---
name: patch-diff
description: "Invoke this skill when the task is recovering a vulnerability from a vendor fix: a CVE with a patch but no public PoC, Patch Tuesday triage, a distribution backport gap, or a closed-source security patch that needs root-cause analysis. Diff the patched and unpatched builds, infer the bug class from the added guards, and verify with a PoC that crashes only the unpatched build."
---

# Patch Diff (N-day recovery from vendor fixes)

Under an **authorized** engagement, recover a vulnerability from the fix that closed it: obtain before and after builds, align symbols, diff the binaries, read the added checks to infer the bug class, then prove the bug with a PoC that reproduces on the unpatched build and runs clean on the patched one.

Attribution: adapted from the `patch-diff-exploit` playbook of [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT License).

## Boundaries

| Allowed | Prohibited |
|---|---|
| Diffing and testing builds in your own lab, on machines covered by written engagement scope, or inside CTF/benchmark ranges | Running a recovered PoC against systems you do not own |
| Writing PoCs that demonstrate the bug (crash, hang, memory-corruption evidence) | Turning a PoC into a deliverable payload |
| Publishing with `{target}`, `{host}`, `{user}` placeholders | Publishing unredacted hostnames, IPs, or usernames |

## When to use

1. **Known CVE, no public PoC.** The advisory names the component and bug class but ships only the fix.
2. **Patch Tuesday triage.** Rank the month's kernel and driver fixes by likely exploitability.
3. **Backport gap.** The mainline fix is merged but a distribution/LTS branch has not picked it up.
4. **Closed-source security patches.** Drivers, engines, virtualization components.

## Core method

```text
patched build (after)  ←── binary diff ──→  unpatched build (before)
                                │
         function-level diff (matched / unmatched / changed)
                                │
       focus on functions with match scores 0.5–0.95
                                │
     read new guards: bounds checks, locks, zeroing, refcounts
                                │
      infer bug class: OOB, race, UAF, info leak, int overflow
                                │
              PoC on the unpatched build
                                │
   verify: unpatched crashes, patched runs clean → bug confirmed
```

## Patch pattern → bug class

| New guard in patched build | Likely bug class |
|---|---|
| `if (a + b < a)`, `__builtin_add_overflow` | integer overflow |
| `KeAcquireSpinLock`, `mutex_lock` | race condition (TOCTOU, double free) |
| `if (idx >= MAX)`, `if (len > buf_size)` | out-of-bounds read or write |
| `RtlZeroMemory`, `memset(struct, 0, ...)` | uninitialized memory info leak |
| `InterlockedDecrement` plus refcount check | UAF, reference-count bug |
| `ProbeForRead` / `ProbeForWrite` | unvalidated user-mode pointer |
| `SeAccessCheck`, capability checks | missing permission check |

## Workflow

**Step 1**: obtain before and after builds (Windows: Microsoft Update Catalog MSU packages; Linux: apt download; third-party: vendor archives). Record sha256 for every artifact.

**Step 2**: align symbols (Windows: `symchk`; Linux: dbgsym packages).

**Step 3**: diff with `ghidriff old_build new_build -o out/` (preferred).

**Step 4**: locate the change. Filter to functions with similarity 0.5–0.95. Read added conditions, loop bounds, and deleted blocks.

**Step 5**: write and verify the PoC. Run against unpatched (crash expected) and patched (clean expected).

## Completion self-check

- [ ] every workflow step was executed, not just read
- [ ] diff, inferred bug class, and PoC artifacts are in the work dir with hashes
- [ ] the patched build was actually tested and its clean result recorded
