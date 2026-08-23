# RC27.32 source convergence

## Purpose

RC27.32 supersedes the immutable RC27.31 candidate after the API genesis
readiness review identified fail-closed recovery and finalization boundaries
that had to be closed before any staging rehearsal or genesis authorization.
API PR #28 adds durable exact-bundle reservation, local-node confirmation
proof, idempotent finalization recovery, ceremony faucet isolation, validator
credential hardening, and focused regression coverage. Its canonical CI,
namespace gates, dependency audit, and secret scan passed before merge.

The legacy backend also advanced after RC27.31 through reviewed release-wrapper
and host-preflight changes. A subsequent review found direct interpolation of
the free-form rollback release input in the remote SSH program. Backend PR #8
closed that boundary by validating the release identity before SSH, transporting
it as data, and prohibiting GitHub expressions in the rollback script. PR and
post-merge CI passed, including tests, migration checks, secret and namespace
scans, dependency audit, and reproducible-archive verification. This backend
commit has not been deployed or activated; staging and production remain on the
prior RC27.31 artifact until separately authorized.

## Candidate source set

The final manifest must be generated only after this protocol tooling change is
reviewed and committed, every listed commit is re-read from the exact remote
`main`, and the coordinated RC27.32 branch and annotated tag exist in all nine
repositories.

| Component | Candidate commit |
| --- | --- |
| Protocol | Pending reviewed RC27.32 manifest-tooling commit based on `25e145fe962fc29cf20d039b7c13ebc8275f47b7` |
| EVM | `d2ccc0a12386a812e99bd6a72481a1d74e2d0d50` |
| Omnichain | `081a5b67e99a53430230d618f05b48415d665cd9` |
| API | `cea4f4f5d37705981605bf110590136031e4f18c` |
| Legacy backend | `67bb6ae75ebbb9dbe6308e35ff2a858e897d41a0` |
| Key of Solomon | `1ee2f30fc5cf283d144d8784faef694061488656` |
| Samuel | `53993dd29bef6805d044f816480f2eae976294d3` |
| Customer web | `e0fb763e2ec01f7529b1e7fc527c8f4b05014eda` |
| Admin portal | `3637b85424c91ba6fd83237faf605d7ef3de4d08` |

## Safety boundary

- Network remains Chia Testnet11 and Ethereum Sepolia.
- `testOnly` remains true.
- Alpha writes, minting, ceremony mode, purchases, and settlement remain
  disabled during the refreeze.
- Existing release branches, tags, manifests, checksums, and evidence remain
  immutable.
- No source manifest is generated with a placeholder commit.
- No genesis draft, funding transaction, contract deployment, signature,
  broadcast, credential mutation, or runtime deployment is part of this
  refreeze.
- Inclusion of a source commit in RC27.32 does not assert that it is active on
  staging or production; runtime activation requires a separate exact-artifact
  deployment authorization and post-deployment verification.
- The API's internal genesis-store schema advances to version 12. Any later
  deployment requires its own backup, migration, restart, and rollback gates.

## Required release sequence

1. Review and merge the RC27.32 manifest-tooling-only protocol change.
2. Re-read all nine remote `main` SHAs and stop on any drift.
3. Create `release/testnet-alpha-rc27.32-20260822` and annotated tag
   `solslot-v2-alpha-rc27.32-20260822` at the exact reviewed source commit in
   each repository.
4. Require all component CI and release-ref checks to pass.
5. Generate the deterministic source manifest and launch-source evidence from
   clean RC27.32 worktrees; verify checksums independently.
6. Regenerate every review request whose source commitment changes. Never
   carry an approval receipt forward from RC27.31.
7. Require separate deployment, credential, and genesis ActionEnvelopes before
   any runtime or chain mutation.

Until these steps pass, production remains fail-closed and is not
genesis-ready.
