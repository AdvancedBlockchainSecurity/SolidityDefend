---
name: ship
description: Full shipping pipeline — version bump, update docs, security checks, FP checks, commit, PR, merge, build, release, and verify. Handles both SolidityDefend and TaskDocs-SolidityDefend repos.
user_invocable: true
---

# /ship — SolidityDefend Shipping Pipeline

Run this skill when the user types `/ship`. It executes the full shipping process in order. Each phase must pass before proceeding to the next. Ask the user for confirmation before creating PRs and before merging.

The user may pass an optional argument describing what's being shipped (e.g., `/ship recall fixes for v2.0.11`). Use this to inform commit messages, PR descriptions, and doc updates.

## Ownership Rules (ALWAYS ENFORCED)

- Git user is `dehvCurtis` — all commits, PRs, and pushes use this account.
- **NEVER** add `Co-Authored-By: Claude` or any Claude/AI attribution to commits, PRs, branches, or comments.
- **NEVER** mention Claude Code, AI, or automated tooling in PR descriptions or commit messages.
- Each destructive git action (force push, reset) requires explicit user approval.

## Repos Involved

| Repo | Path | Remote |
|------|------|--------|
| SolidityDefend | `/home/pwner/Git/SolidityDefend` | `AdvancedBlockchainSecurity/SolidityDefend` |
| TaskDocs | `/home/pwner/Git/TaskDocs-SolidityDefend` | `AdvancedBlockchainSecurity/TaskDocs-SolidityDefend` |

---

## Phase 1: Version Bump and Documentation

### 1a. Bump version in `Cargo.toml`

- Update the `version` field in the root `Cargo.toml`.
- Follow semver: patch for fixes, minor for new features/detectors, major for breaking changes.
- Ask the user to confirm the new version number before proceeding.

### 1b. If any detectors were removed, update `docs/REMOVED_DETECTORS.md`

Add an entry for each removed detector with: detector ID, filename, version removed, and reason. This prevents rebuilding the same detector twice.

### 1c. Update `docs/CHANGELOG.md` in SolidityDefend

- Add a new version entry (or update the current one) at the top of the changelog.
- Follow the existing Keep a Changelog format with `### Fixed`, `### Added`, `### Changed` sections.
- Summarize every change being shipped with enough detail for users to understand impact.

### 1d. Update any other docs in `docs/` that are affected

- If detectors were added/changed, update `docs/DETECTOR-TYPES.md` if it lists detector counts or capabilities.
- If CLI behavior changed, update `docs/CLI.md` or `docs/USAGE.md`.
- If validation/testing changed, update `docs/VALIDATION.md` or `docs/TESTING.md`.

### 1e. Update TaskDocs-SolidityDefend

- Update `/home/pwner/Git/TaskDocs-SolidityDefend/current-task.md` with the current work status.
- If new FP analysis was done, add results under `fp-testing/results/`.
- If security analysis was done, add results under `security/`.
- Keep docs concise — tables and bullet points, not walls of text.

---

## Phase 2: Security Checks

Run these checks and report results. All must pass.

### 2a. Build release binary

```bash
cargo build --release 2>&1
```

If build fails, stop and fix before continuing.

### 2b. Run full test suite

```bash
cargo test --workspace --lib 2>&1
```

Report total test count and pass/fail. Must be 0 failures.

### 2c. Check for credential/secret leaks

```bash
# Scan staged and modified files for secrets
git diff --name-only HEAD | xargs grep -l -i -E '(password|secret|api_key|private_key|token\s*=)' 2>/dev/null || echo "No secrets found"
```

### 2d. Check for unsafe code

```bash
grep -rn "unsafe " crates/ --include="*.rs" | grep -v "// SAFETY:" | head -20
```

Any new `unsafe` blocks without `// SAFETY:` comments must be reviewed.

### 2e. Verify detector registration integrity

```bash
cargo test -p detectors --lib registry 2>&1 | tail -5
```

This runs 3 checks: count >= baseline, all detectors have valid IDs/names/descriptions, no duplicate IDs. Must be 0 failures.

Also verify the binary count matches `docs/baseline/README.md`:
```bash
./target/release/soliditydefend --list-detectors 2>&1 | grep -cE '^\s+[a-z]'
```

Report if changed and update the baseline if the change is intentional.

---

## Phase 3: False Positive Checks

### 3a. Run ground truth validation

```bash
cargo test -p detectors --lib 2>&1 | tail -5
```

All detector unit tests must pass. Report the count.

### 3b. Scan clean contracts (must be 0 findings)

```bash
./target/release/soliditydefend tests/contracts/clean_examples/ --format json 2>&1 | awk '/^\{$/,/^\}$/' | jq '.findings | length'
```

Must output `0`. Any findings here are false positives — stop and fix.

### 3c. Scan FP benchmark contracts

```bash
./target/release/soliditydefend tests/contracts/fp_benchmarks/ --format json 2>&1 | awk '/^\{$/,/^\}$/' | jq '.findings | length'
```

Report finding count. Compare to previous baseline if available.

### 3d. Run external validation corpus (if available)

```bash
if [ -d ~/Git/vulnerable-smart-contract-examples ]; then
    ./target/release/soliditydefend ~/Git/vulnerable-smart-contract-examples/contracts/solidity/ --format json 2>&1 | awk '/^\{$/,/^\}$/' | jq '{total: (.findings | length), errors: (.errors | length)}'
fi
```

Report total findings and errors.

---

## Phase 4: Commit, PR, and Merge

### 4a. Handle SolidityDefend repo

1. **Check for changes:**
   ```bash
   cd /home/pwner/Git/SolidityDefend && git status && git diff --stat
   ```

2. **Create branch** (if not already on a feature branch):
   ```bash
   git checkout -b <branch-name>
   ```
   Branch naming: `fix/<description>`, `feat/<description>`, `docs/<description>`, or `release/v<version>`.

3. **Stage and commit:**
   - Stage only relevant files (never `git add -A`).
   - Write a clear commit message summarizing the changes. NO Claude attribution.
   - Example format:
     ```
     fix: improve delegatecall detector recall for direct address params

     - Remove deferral to non-existent dangerous-delegatecall detector
     - Add loop body recursion for unchecked-external-call
     - Add 15 new admin verb patterns to access control detector
     ```

4. **Push branch:**
   ```bash
   git push -u origin <branch-name>
   ```

5. **Create PR:**
   ```bash
   gh pr create --title "<title>" --body "<description>"
   ```
   PR description format:
   ```
   ## Summary
   - Bullet point summary of changes

   ## Changes
   - Detailed list of what changed and why

   ## Testing
   - [ ] All unit tests pass (N/N)
   - [ ] Ground truth recall matches `docs/baseline/README.md`
   - [ ] Clean contract FP rate: 0%
   - [ ] External validation: N findings, 0 errors

   ## Security
   - [ ] No secrets in diff
   - [ ] No new unsafe blocks
   - [ ] Detector count matches `docs/baseline/README.md`
   ```
   **Do NOT mention Claude Code, AI, or automated tools anywhere in the PR.**

6. **Ask user to confirm merge**, then:
   ```bash
   gh pr merge <pr-number> --merge
   ```

7. **Return to main:**
   ```bash
   git checkout main && git pull origin main
   ```

### 4b. Handle TaskDocs-SolidityDefend repo

Only if changes were made in Phase 1c.

1. **Check for changes:**
   ```bash
   cd /home/pwner/Git/TaskDocs-SolidityDefend && git status
   ```

2. **Create branch, commit, push, PR, merge** — same process as 4a.
   - Branch naming: `docs/<description>`
   - Commit message: `docs: update for <what changed>`
   - PR description: Summary of doc changes. NO Claude attribution.

3. **Return to main:**
   ```bash
   git checkout main && git pull origin main
   ```

### 4c. Final verification

After all merges:
```bash
cd /home/pwner/Git/SolidityDefend && git log --oneline -3
cd /home/pwner/Git/TaskDocs-SolidityDefend && git log --oneline -3
```

Report the final state: branch, latest commits, version.

---

## Phase 5: Tag and Release

Only proceed after Phase 4 merges are complete and main is up to date.

GitHub Actions (`.github/workflows/release.yml`) handles building and releasing automatically when a tag is pushed. It builds for 5 targets (Linux x86_64, Linux aarch64, macOS aarch64, macOS x86_64, Windows x86_64), generates SHA256 checksums, and creates the GitHub release with all binaries. Do NOT create a release manually.

### 5a. Create and push git tag

```bash
cd /home/pwner/Git/SolidityDefend && git checkout main && git pull origin main
git tag v<version>
git push origin v<version>
```

Tag must match the version in `Cargo.toml`. Ask the user to confirm before pushing the tag.

### 5b. Verify CI release

Wait for the GitHub Actions release workflow to complete, then verify:

```bash
gh run list --workflow=release.yml --limit 1
gh release view v<version>
```

Confirm:
- CI workflow succeeded
- Release is published (not draft)
- All 5 platform binaries are attached
- SHA256SUMS.txt is attached
- Release notes were extracted from `docs/CHANGELOG.md`

Report the release URL to the user. If CI failed, investigate with `gh run view <run-id> --log-failed`.

---

## Error Handling

- If any phase fails, stop and report the failure clearly.
- Do not skip phases or continue past failures.
- If a PR fails CI, investigate and fix before re-attempting.
- If merge conflicts occur, resolve them and ask for user confirmation before force-resolving.
