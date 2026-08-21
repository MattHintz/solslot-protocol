# RC27.31 source convergence

## Purpose

RC27.31 supersedes the immutable RC27.30 candidate after its fresh Key of
Solomon dependency audit detected `RUSTSEC-2026-0258` in transitive dependency
`h2` version 0.4.15. RC27.30 branches and tags remain preserved as failed
candidate evidence and are not rewritten.

Key of Solomon PR #22 updates only `Cargo.lock`, from `h2` 0.4.15 to the fixed
0.4.16 release. Its live RustSec audit, locked tests, formatting, and clippy
checks passed before merge. No application code, puzzle code, transaction
construction, signing, custody, settlement, or authorization behavior changed.

## Candidate source set

The final manifest must be generated only after the protocol tooling change is
reviewed and committed, every listed commit is re-read from the exact remote
`main`, and the coordinated RC27.31 branch and annotated tag exist in all nine
repositories.

| Component | Candidate commit |
| --- | --- |
| Protocol | Pending reviewed RC27.31 manifest-tooling commit based on `4d46f722025d4e8557048f3dbfe71fb98204e630` |
| EVM | `d2ccc0a12386a812e99bd6a72481a1d74e2d0d50` |
| Omnichain | `081a5b67e99a53430230d618f05b48415d665cd9` |
| API | `40e05eda10fb1372caddf60eee5ad7c8e1c79497` |
| Legacy backend | `d1e97057a48f1eb046d3424a05ed99ed6548f2b9` |
| Key of Solomon | `1ee2f30fc5cf283d144d8784faef694061488656` |
| Samuel | `53993dd29bef6805d044f816480f2eae976294d3` |
| Customer web | `e0fb763e2ec01f7529b1e7fc527c8f4b05014eda` |
| Admin portal | `3637b85424c91ba6fd83237faf605d7ef3de4d08` |

## Safety boundary

- Network remains Chia Testnet11 and Ethereum Sepolia.
- `testOnly` remains true.
- Alpha writes, minting, ceremony mode, purchases, and settlement remain
  disabled.
- No existing RC27.6 or RC27.30 tag, branch, manifest, checksum, or evidence is
  rewritten.
- No source manifest is generated with a placeholder commit.
- No genesis draft, funding transaction, contract deployment, signature,
  broadcast, or runtime deployment is part of this refreeze.

## Required release sequence

1. Review and merge the RC27.31 manifest-tooling-only protocol change.
2. Re-read all nine remote `main` SHAs and stop on any drift.
3. Create `release/testnet-alpha-rc27.31-20260821` and annotated tag
   `solslot-v2-alpha-rc27.31-20260821` at the exact reviewed source commit in
   each repository.
4. Require all component CI and release-ref checks to pass.
5. Generate the deterministic source manifest and launch-source evidence from
   clean RC27.31 worktrees; verify checksums independently.
6. Regenerate any review request whose commitment changes. Never carry an
   approval receipt forward from RC27.6 or RC27.30.
7. Require a separate deployment or genesis ActionEnvelope before any runtime
   mutation.

Until these steps pass, production remains fail-closed and is not
genesis-ready.
