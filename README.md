# Implementation Plan (v6, Rust): Crygpit — Zero-Metadata Encrypted Mirrors

## 0. Goal & Threat Model

GitHub (and anyone with read or push access to the outer repo) should learn **nothing** except that encrypted blobs exist. Only members can see the history, files, contributors, member keys and config.

| Adversary | Can | Must NOT be able to |
| :--- | :--- | :--- |
| GitHub / public reader | Read outer repo | Learn contents, names, members, or key IDs |
| Outsider with outer push access | Replace or delete blobs | Get members to accept forged or old content, or add a recipient |
| Malicious member | Push valid vaults | Run code on other members' machines, or add members silently |
| Removed member | Keep old clones | Read anything pushed after removal |

## 1. Local Layout

`crygpit init ~/code/project` →

```
~/code/project.crypt/
├── .git/                    OUTER repo → GitHub (linear history, never merged)
├── .gitignore           ✔   allow-list
├── vault/               ✔   encrypted segments (only content GitHub sees)
│   └── 000001.gpg
├── .crygpit/                LOCAL only, ignored
│   ├── local.toml           signing key, vault dir name, prefs
│   ├── trust.toml           pinned member fingerprints (TOFU), last accepted seq + chain hash
│   ├── keyring.kbx          project-local public keyring (members' keys)
│   ├── state.toml           last pushed fingerprint (refs + meta hash)
│   └── lock
└── project/                 INNER repo, plaintext, NO remote, ignored by outer
    ├── .git/
    └── src/ ...
```

Outer `.gitignore`:
```
*
!.gitignore
!vault/
!vault/*.gpg
```

## 2. Segment Format (`vault/NNNNNN.gpg`)

```
gpg --sign --encrypt --throw-keyids -z 0
└── tar (normalized headers: uid/gid 0, no uname, mtime 0, sorted)
    ├── meta.toml           seq, prev_hash, kind = "full"|"incremental"(phase 2),
    │                       base_seq, bundle_sha256, created_at, crygpit version
    ├── members.toml        [[member]] fpr, label, added_by, added_at
    │                       [[removed]] fpr, removed_by, removed_at
    ├── config.toml         name, extra_ignore, pad, date_mode
    ├── keys/<FPR>.asc      public keys of all current members
    ├── repo.bundle         git bundle of refs/heads/* + refs/tags/* (objects + refs only)
    └── pad                 random bytes (Padmé)
```

Why each piece is there:
- **Git bundle, not raw `.git`.** No hooks, config, index, reflog or local paths ever cross machines. Git alone decides what's included, so tracked files are never dropped.
- **Sign then encrypt.** The signer is authenticated, and their identity stays hidden inside the ciphertext.
- **`seq` + `prev_hash`.** Rollback protection (§5).
- **No extra compression.** Bundle objects are already zlib-compressed, and GPG compression is off (`-z 0`), so the size depends only on the padding bucket.
- **Padmé padding.** The size leaks only about log-log bits, with at most ~12% overhead (vs up to 100% for power-of-two).

## 3. Multiple Recipients

PGP is hybrid: one random session key encrypts the data, and that session key is wrapped once per recipient (one anonymous header packet each with `--throw-keyids`). Any single recipient's private key decrypts the file.

- Recipients = all current members, **always plus yourself**.
- Encryption uses the project-local keyring with explicit full fingerprints and `--trust-model always`. Crygpit enforces trust through fingerprint pinning (§5), so gpg's web-of-trust prompts don't block it. Members' keys are not added to your main keyring.
- Before every push, check that each recipient key exists, isn't expired or revoked, and can encrypt.

## 4. Members

| Command | Behavior |
| :--- | :--- |
| `crygpit member add <key.asc \| FPR> [--label L]` | Pins the key locally and adds it to `members.toml` + `keys/`. Takes effect on next push. |
| `crygpit member rm <FPR>` | Moves it to `[[removed]]`; the next push excludes that key. |
| `crygpit member ls` | Current and removed members, with who changed what and when. |

> [!WARNING]
> Removal only blocks **future** pushes. A removed member can still decrypt older segments in git history and may already have clones. Rotate any secrets stored in the project.

## 5. Authentication & Trust (fixes forgery / rollback)

On every decrypt (clone, pull, push-after-fetch, ls, extract):

1. **Decrypt success** is decided from `--status-fd`: requires `DECRYPTION_OKAY` and integrity OK, and no `DECRYPTION_FAILED`. The exit code is ignored, because with `--throw-keyids` gpg returns rc=2 even on success (verified).
2. **Signature required:** `GOODSIG` + `VALIDSIG`. The signer's primary fingerprint (last field of `VALIDSIG`) must be in `trust.toml`. Reject on `BADSIG`, `ERRSIG`, `REVKEYSIG`, `NO_PUBKEY`, or an unsigned payload. `EXPKEYSIG` gives a warning plus confirmation.
3. **Member changes** compared with `trust.toml` are shown as a diff and need explicit confirmation (`--accept-members` for scripts). Removals are accepted automatically, since they only reduce trust.
4. **Rollback / replay protection:** `seq` must be greater than the last accepted `seq`, and `prev_hash` must equal the hash of the last accepted segment. Otherwise reject with "vault rolled back or forked".
5. **First clone (TOFU):** shows the signer and the member list with fingerprints, and asks for confirmation. Only after that is anything pinned. `--expect-signer FPR` lets you verify out-of-band without a prompt.

Residual risk: a "freeze" (an attacker deletes new pushes so you keep seeing old state) can't be prevented without an out-of-band channel. `status` shows the last accepted `seq` and its date so members can compare.

## 6. Metadata Hardening

| Leak | Mitigation |
| :--- | :--- |
| Recipient key IDs | `--throw-keyids` (always) |
| Signer identity | Signature is inside the encryption |
| Members / config / project name | Inside the payload only. Nothing committed in plaintext. |
| Outer commit author / email | `crygpit <crygpit@invalid>` via `GIT_AUTHOR_*` / `GIT_COMMITTER_*` |
| Outer commit message | Constant `update` |
| Outer commit dates | `date_mode = fixed` (default) \| `day` \| `real` |
| Exact size | Padmé padding |
| Tool fingerprint | Vault dir name configurable at `init` (`--vault-dir`). `clone` discovers it from the `.gitignore` allow-list. |

**Cannot be hidden:** the number of recipients (one header packet each; optional decoys later), the OpenPGP algorithm family, approximate size, the number and timing of pushes, and the GitHub account and repo name.

## 7. CLI

| Command | Behavior |
| :--- | :--- |
| `crygpit init <path> [--remote URL] [--member FPR...] [--vault-dir D] [--yes]` | Transactional (§9). Shows the default ignores for confirmation, creates the layout, signs and pushes the first full segment. |
| `crygpit push [-m MSG]` | §8 push algorithm. |
| `crygpit clone <remote> [dest] [--expect-signer FPR]` | Clones the outer repo, verifies the latest segment (TOFU), fetches the bundle into a fresh inner repo, checks out the default branch, pins the members. |
| `crygpit pull` | Outer fetch, then verify the new segments and merge inner (§8). |
| `crygpit ls [--ref R]` | Decrypts into a temp bare repo in `$XDG_RUNTIME_DIR` (tmpfs) and runs `git ls-tree -r`. Deleted afterwards. |
| `crygpit extract <file> [--ref R] [-o dir]` | Same, using `git show R:file`. Works without a full checkout. |
| `crygpit status` | Inner dirty / unpushed, outer ahead/behind, last accepted seq and date, key health. |
| `crygpit member add/rm/ls` | §4 |
| `crygpit doctor` | Checks gpg/git versions, signing key, whether the agent can sign without a TTY, recipient key validity, the remote, and segment size limits. |
| `crygpit unwrap` | Moves `project/` back next to `project.crypt/`. |

## 8. Core Algorithms

### Change detection
`fingerprint = sha256(sorted "git for-each-ref refs/heads refs/tags" output + HEAD symref + hash(members, config))`.
This is compared with `state.toml`. Index and stat noise is ignored, so plain `git status` doesn't count as a change.

### Push (fetch → merge → repack → retry; outer is never merged)
```
lock
inner: if dirty → git add -A && git commit (MSG | "crygpit: snapshot <ts>")
loop (max 5 attempts):
    outer: git fetch
    if remote has segments newer than our last accepted seq:
        verify (§5) → fetch bundle into refs/crygpit/incoming/* → merge inner (below)
        on conflict → stop, leave the inner repo in normal merge state, tell user to resolve and re-run push
    if fingerprint unchanged and nothing new → exit "up to date"
    build segment (seq = last+1, prev_hash = hash(last)) → sign+encrypt → vault/NNNNNN.gpg.tmp → rename
    outer: commit on top of origin head (anonymized) → git push (no force)
    if push rejected (someone pushed in between) → reset outer to origin, continue loop
update state.toml + trust.toml, unlock
```

### Inner merge (pull and push)
- The bundle is fetched into `refs/crygpit/incoming/heads/*` and `tags/*`. Hooks are never involved, because it's a plain `git fetch` from a file.
- **Current branch:** fast-forward if possible, otherwise `git merge` (a normal merge commit). On conflicts, the usual git conflict state is left for the user.
- **Other branches:** fast-forward if possible. If they diverged, keep the incoming version as `refs/crygpit/incoming/...` and report it.
- **New branches/tags:** created. Tags that conflict with local ones: keep local and warn.
- Local uncommitted work is auto-committed before merging.

## 9. Transactional `init`

1. **Validate everything first:** the path exists, `<path>.crypt` doesn't, the path isn't nested in another `.crypt`, the source and its parent are on the same filesystem, the inner repo has no remote (unless `--allow-remote`), the signing key works, the recipient keys are valid, and the remote is reachable (if given).
2. Build the outer skeleton in a sibling temp dir `<path>.crypt.tmp-XXXX`.
3. `rename(<path>, tmp/project)`, then `git init` the inner repo if needed and write the confirmed excludes.
4. Create the first segment and the outer commit.
5. `rename(tmp, <path>.crypt)`. Then push. A failed push is not fatal; it can be retried with `crygpit push`.
6. Any failure in steps 2–5 is undone: the project is moved back and the temp dir removed. A journal file in the temp dir allows recovery after a crash (`crygpit init --recover`).

## 10. Ignore Defaults

These are shown at `init` and need confirmation (they can be edited). They're written to the inner `.git/info/exclude`, so the tracked `.gitignore` stays untouched. They affect **untracked files only**; files you already track stay tracked.

```
node_modules/  target/  dist/  .next/  .nuxt/  .venv/  venv/  __pycache__/
*.pyc  .tox/  .mypy_cache/  .pytest_cache/  .gradle/  *.log  .DS_Store
```
Patterns that are sometimes real source (`build/`, `out/`, `vendor/`, `.vscode/`, `.idea/`) are offered as optional.

## 11. Non-interactive Use

- gpg runs through the agent. When there's no TTY, crygpit checks beforehand (`doctor` logic) and fails with a clear message instead of hanging on pinentry.
- `--yes` / `--accept-members` / `--expect-signer` cover scripted runs explicitly. Nothing security-relevant is accepted by default.

## 12. Size Limits

- **Phase 1:** each push writes a **full** segment. If a padded segment would exceed **95 MB** (GitHub rejects 100 MB), push refuses with a message pointing to phase 2 features.
- **Phase 2:**
  - **Incremental segments:** `git bundle create - <last-pushed-tips>..` gives `kind = "incremental"`, with a full snapshot every N segments or when the incremental total exceeds X% of a full one.
  - **Chunking:** segments split into ≤32 MiB parts `NNNNNN.K.gpg`, each signed and encrypted on its own and listed in `meta.toml`.
  - **`crygpit compact`:** writes a new full segment and deletes older ones from the working tree. An optional history rewrite (orphan branch + force push) needs confirmation and comes with a coordination warning for other members.
  - **Decoy recipients** to hide the member count.

## 13. Architecture

Crygpit shells out to `gpg` and `git`, so it works with your keyring, agent, pinentry, YubiKey and SSH setup. Both sit behind traits (`Crypto`, `Vcs`), so native backends could be added later.

Crates: `clap`, `serde`, `toml`, `tar`, `sha2`, `rand`, `tempfile`, `anyhow`, `thiserror`, `chrono`; dev: `assert_cmd`, `predicates`.

```
src/
├── main.rs  cli.rs
├── paths.rs          root discovery, layout, vault dir discovery
├── config.rs         config.toml / local.toml
├── members.rs        members.toml, key export/import (project keyring)
├── trust.rs          trust.toml: pinning, seq/prev_hash checks, member diff + prompt
├── state.rs          fingerprint, lock
├── segment.rs        build/parse segment tar (meta, keys, bundle, Padmé pad)
├── gpg.rs            Crypto trait, GnuPG impl, status-fd parser (decrypt/verify verdicts)
├── git.rs            Vcs trait: bundle create/fetch, merge, for-each-ref, anonymized outer commits
├── sync.rs           push loop, pull, inner merge strategy
├── init.rs           transactional init + recover, unwrap
└── commands/         init push clone pull ls extract status member doctor unwrap
tests/e2e.rs
```

## 14. Test Plan (`tests/e2e.rs`)

Each test uses a temp `GNUPGHOME`, keys for Alice, Bob, Carol and Mallory (no passphrase), and a local bare repo standing in for GitHub.

| # | Scenario | Expectation |
| :- | :--- | :--- |
| 1 | `init` | Remote contains only `.gitignore` + `vault/000001.gpg`. Project moved. |
| 2 | Metadata | Empty-keyring `--list-packets` shows only `keyid 0000…`. Outer log has a generic author, message and date. |
| 3 | Padding | Segment sizes match Padmé buckets. |
| 4 | Ignores | `node_modules/` and `target/` aren't committed or bundled. A tracked `build/` file **is** included. |
| 5 | Change detection | `git status` alone → push says "up to date". |
| 6 | Multi-member | Alice adds Bob. Bob clones (TOFU), commits, pushes. Alice pulls and fast-forwards. |
| 7 | Concurrent push | Alice and Bob both push from the same base → the second retries, merges inner, succeeds. Outer history is linear. |
| 8 | Inner conflict | Same line edited by both → push stops with inner merge state. Resolve, re-push. |
| 9 | Forgery | Mallory (non-member, has remote push access) writes a vault encrypted to Alice and signed by Mallory → rejected. |
| 10 | Member injection | Bob adds Mallory → Alice's pull shows the diff and needs confirmation. |
| 11 | Rollback | Old valid segment re-pushed as newest → rejected (seq / prev_hash). |
| 12 | Hooks | Bob's inner repo has a `post-checkout` hook → it doesn't appear on Alice's machine. |
| 13 | Removal | Carol removed → can't decrypt the new segment, can still read the old one (documented). |
| 14 | gpg rc=2 | Multiple local secret keys + `--throw-keyids` → decrypt succeeds via status-fd. |
| 15 | Transactional init | Failure injected after the move → project restored to its original path. |
| 16 | Size guard | Payload > 95 MB → push refuses with a clear message. |
| 17 | `ls` / `extract` | Correct listing and file content; temp dir removed. |
| 18 | `unwrap` | Original location restored. |

## 15. Prior Art

[git-remote-gcrypt](https://spwhitton.name/tech/code/git-remote-gcrypt/) encrypts whole git remotes with gpg and supports multiple participants and hidden recipients. Before implementing, review its manifest and concurrent-push handling. Crygpit's differences: built-in member key distribution with signatures and pinning, rollback protection, padding, anonymous outer commits, and the `.crypt` wrapper / auto-commit / ignore workflow.

## 16. Delivery Phases

1. **Phase 1:** everything above except §12 phase 2 items.
2. **Phase 2:** incremental segments, chunking, `compact`, decoy recipients.

## 17. Toolchain

A stable Rust toolchain exists at `~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/`, but `cargo` is not on PATH. Fix PATH/rustup, or the build will call cargo by its full path. Requires `gpg` ≥ 2.2 and `git` ≥ 2.30 (checked by `doctor`).
