# RC27.33 source convergence

## Purpose

RC27.33 supersedes the immutable RC27.32 candidate after the official
Testnet11 pre-initialization review found that a guided owner claim could reuse
an active ceremony without proving that its protected draft matched the new
release policy. API PR #29 closes that downgrade boundary atomically before
claim consumption. It also makes independent review server-selected for the
official guided flow, keeps fresh Sepolia deployment evidence before plan
creation, moves the plan-bound audit to approved-plan strict preflight, and
keeps Base Sepolia payment ownership outside genesis while still requiring it
before payment activation.

The corrected API patch received a complete four-file security diff review
with zero reportable findings. Its focused 64-test set, namespace and
credential gates passed locally. Pull-request and post-merge CI passed the full
test suite, dependency audit, compile/import, namespace, and secret gates.

An independent review of this release tool also found that its historical
release-ref check trusted local tracking refs and accepted a lightweight tag.
RC27.33 now requires the canonical repository specifically at `origin`, reads
live remote `main` and tag refs, requires the annotated tag object's peeled
commit, rejects missing, duplicate, or unexpected refs, and cross-checks the
local tracking and tag objects. Release evidence cannot be marked verified
from stale local refs alone.

## Candidate source set

The final manifest must be generated only after this protocol tooling change
is reviewed and committed, every listed commit is re-read from exact remote
`main`, and the coordinated RC27.33 branch and annotated tag exist in all nine
repositories.

| Component | Candidate commit |
| --- | --- |
| Protocol | Pending reviewed RC27.33 manifest-tooling commit based on `c00446ce4cd223c3baba760b5bb9589dcb49e62c` |
| EVM | `d2ccc0a12386a812e99bd6a72481a1d74e2d0d50` |
| Omnichain | `081a5b67e99a53430230d618f05b48415d665cd9` |
| API | `1c6aa78177daa9d371dbcd8623146c063af304a4` |
| Legacy backend | `67bb6ae75ebbb9dbe6308e35ff2a858e897d41a0` |
| Key of Solomon | `1ee2f30fc5cf283d144d8784faef694061488656` |
| Samuel | `53993dd29bef6805d044f816480f2eae976294d3` |
| Customer web | `e0fb763e2ec01f7529b1e7fc527c8f4b05014eda` |
| Admin portal | `3637b85424c91ba6fd83237faf605d7ef3de4d08` |

## Official Testnet11 policy

1. The official guided flow uses the protected server review class
   `independent-release-review`; browser input cannot select or downgrade it.
2. A claim can resume an active ceremony only when its canonical protected
   draft exactly matches the current release policy; a mismatch returns a
   conflict without consuming the one-time claim.
3. Fresh Sepolia identity deployment evidence is present before the plan is
   built and is reverified against live contract code at strict preflight.
4. Independent approval is plan-bound, becomes blocking after owner-plus-one
   plan approval, and is revalidated at strict preflight.
5. `internal-engineering-testnet` is an explicit server-selected disposable
   workflow only and must never be represented as the official genesis.
6. Base Sepolia payment ownership and Stripe rehearsal do not block genesis,
   but presale and purchase activation remain locked until their separate
   post-genesis gates are complete.

## Safety boundary

- Network remains Chia Testnet11 and Ethereum Sepolia.
- `testOnly` remains true.
- Alpha writes, minting, launch control, ceremony mode, purchases, payment
  ownership activation, and settlement remain disabled during the refreeze.
- Existing release branches, tags, manifests, checksums, and evidence remain
  immutable.
- No source manifest is generated with a placeholder commit.
- No genesis draft or claim, funding transaction, contract deployment,
  administrator enrollment, signature, broadcast, credential mutation, or
  customer write is part of this refreeze.
- Inclusion of a source commit in RC27.33 does not assert runtime activation;
  staging deployment requires the protected backup, isolated restore, fresh
  closed state root, and exact-artifact verification approved separately.

## Required release sequence

1. Review and merge the RC27.33 manifest-tooling-only protocol change.
2. Re-read all nine remote `main` SHAs and stop on any drift.
3. Create `release/testnet-alpha-rc27.33-20260823` and annotated tag
   `solslot-v2-alpha-rc27.33-20260823` at the exact reviewed source commit in
   each repository.
4. Require all component CI and release-ref checks to pass.
5. Generate the deterministic source manifest and launch-source evidence from
   clean RC27.33 worktrees; verify checksums independently.
6. Regenerate every review request whose source commitment changes. Never
   carry an approval receipt forward from RC27.32.
7. Create and prove the protected staging backup and isolated restore before
   any deployment or service mutation.
8. Keep staging closed and require a separate initialization ActionEnvelope
   before any owner claim, ceremony row, funding, signing, or broadcast.

Until these steps pass, staging remains fail-closed and is not genesis-ready.
