# RC27.30 source convergence

## Purpose

RC27.30 reconciles the signed nine-repository launch manifest with the
security-reviewed customer release that is actually served on Testnet11. It
does not change puzzle code, transaction construction, signing, custody,
settlement, authorization, or launch gates.

The preserved RC27.6 manifest binds customer web commit
`56812b20d89791a4a5150a1c2ff30c8ae26cbe85`. On 2026-08-21, production and
staging served customer release RC27.29 at
`1da8ab95188f19c18aa12217bb1046af00475ef2`, while the customer repository's
current `main` was `e0fb763e2ec01f7529b1e7fc527c8f4b05014eda`. The difference from the
deployed commit is deployment-workflow-only.

The post-genesis gate requires every live consumer `sourceSha` to match the
corresponding SHA in the signed artifact exactly. Claiming the old RC27.6
customer SHA for a newer deployed customer build would therefore be invalid.

## Candidate source set

The final manifest must be generated only after the protocol tooling change is
reviewed and committed, every listed commit is the exact remote `main`, and the
coordinated RC27.30 branch and annotated tag exist in all nine repositories.

| Component | Candidate commit |
| --- | --- |
| Protocol | Pending reviewed RC27.30 manifest-tooling commit based on `03cb5825d071291f03c29b5eb84edfbf3fa82799` |
| EVM | `d2ccc0a12386a812e99bd6a72481a1d74e2d0d50` |
| Omnichain | `081a5b67e99a53430230d618f05b48415d665cd9` |
| API | `40e05eda10fb1372caddf60eee5ad7c8e1c79497` |
| Legacy backend | `d1e97057a48f1eb046d3424a05ed99ed6548f2b9` |
| Key of Solomon | `2a6a450aee0f3629578329278ab07915d5760789` |
| Samuel | `53993dd29bef6805d044f816480f2eae976294d3` |
| Customer web | `e0fb763e2ec01f7529b1e7fc527c8f4b05014eda` |
| Admin portal | `3637b85424c91ba6fd83237faf605d7ef3de4d08` |

## Safety boundary

- Network remains Chia Testnet11 and Ethereum Sepolia.
- `testOnly` remains true.
- Alpha writes, minting, ceremony mode, purchases, and settlement remain
  disabled.
- No existing RC27.6 tag, branch, manifest, checksum, or evidence file is
  rewritten.
- No source manifest is generated with a placeholder commit.
- No genesis draft, funding transaction, contract deployment, signature, or
  broadcast is part of this refreeze.

## Required release sequence

1. Review and merge the RC27.30 manifest-tooling-only protocol change.
2. Re-read all nine remote `main` SHAs and stop on any drift.
3. Create `release/testnet-alpha-rc27.30-20260821` and annotated tag
   `solslot-v2-alpha-rc27.30-20260821` at the exact reviewed source commit in
   each repository.
4. Require all component CI and release-ref checks to pass.
5. Generate the deterministic source manifest and launch-source evidence from
   clean RC27.30 worktrees; verify checksums independently.
6. Regenerate any review request whose commitment changes. Never carry an
   approval receipt forward from RC27.6.
7. Deploy the exact RC27.30 API, customer, and protected admin consumers with
   every write gate still false, then capture a new release attestation.

Until these steps pass, production is healthy and fail-closed but is not
genesis-ready.
