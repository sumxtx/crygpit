# Implementation Plan (v5, Rust): Crygpit — Zero-Metadata Encrypted Mirrors

## 0. Goal

GitHub sees **one opaque blob**. Everything else is inside the encryption and visible only to people who can decrypt: file names, history, commit messages, contributors, member keys, the project name and the config.

## 1. Layout

`crygpit init ~/code/project` →

```
~/code/project.crypt/
├── .git/                OUTER repo → GitHub
├── .gitignore       ✔   allow-list (only the files marked ✔)
├── vault.gpg        ✔   the only content GitHub sees (generic name, no project name)
├── .crygpit/            LOCAL only, ignored
│   ├── state.toml       last plaintext hash, lock
│   └── cache/           decrypted copy of meta (members, config)
└── project/             INNER repo, plaintext, NO remote, ignored by outer
    ├── .git/
    └── src/ ...
```

Outer `.gitignore`:
```
*
!.gitignore
!vault.gpg
```

## 2. What's Inside `vault.gpg` (encrypted payload)

```
tar root
├── .crygpit-meta/
│   ├── config.toml       name = "project", extra_ignore, pad, date_mode ...
│   ├── members.toml      [[member]] fingerprint, label ("alice@…"), added_by, added_at
│   └── keys/
│       ├── <FPR_A>.asc   exported PUBLIC keys of every member
│       └── <FPR_B>.asc
├── .crygpit-pad          random padding (see §5)
└── project/              the project, incl. project/.git
```

Every member who decrypts gets the full recipient list **and** their public keys, so they can re-encrypt for everyone on their next push without any out-of-band key exchange.

## 3. Multiple Recipients (how PGP does it)

PGP is hybrid encryption, and multiple recipients are built in:
1. A random **session key** encrypts the data once (AES).
2. The session key is encrypted separately to each recipient's public key, giving one small header packet per recipient.
3. Any one recipient's private key unlocks the session key, and with it the whole file.

```
gpg -e --throw-keyids -r FPR_A -r FPR_B -r FPR_C
```
Verified locally: 3 anonymous header packets (`keyid 0000000000000000`), and Bob alone can decrypt.

Crygpit rules:
- Recipients = all fingerprints in `members.toml`, **always plus your own key** (otherwise you'd lock yourself out).
- Before each push, check that every recipient key is present, not expired, not revoked and can encrypt. Abort if any fails.
- Always use full fingerprints, never short IDs.

## 4. Members

| Command | Behavior |
| :--- | :--- |
| `crygpit member add <key.asc \| FPR>` | Imports the key, adds it to `members.toml`, copies the public key into `keys/`. Takes effect on next push. |
| `crygpit member rm <FPR>` | Removes the member; the next push re-encrypts without them. |
| `crygpit member ls` | Lists members (from the decrypted meta cache). |

> [!WARNING]
> Removal is not retroactive. A removed member can still decrypt every **older** `vault.gpg` in git history, and may already have cloned it. Treat removal as "no future access" and rotate any secrets the project contains.

## 5. Metadata Hardening

| Leak | Mitigation | Default |
| :--- | :--- | :--- |
| Recipient key IDs in header | `--throw-keyids` | **on** (always) |
| Recipients/config in a committed file | Moved inside the payload (§2) | on |
| Project name in filename | Fixed name `vault.gpg` | on |
| Outer commit author/email | `crygpit <crygpit@invalid>` via `GIT_AUTHOR_*`/`GIT_COMMITTER_*` | on |
| Outer commit message | Constant `update` | on |
| Outer commit dates | `date_mode = fixed` (constant date) \| `day` (rounded) \| `real` | `fixed` |
| Exact payload size | Pad the plaintext up to a bucket (`pad = "pow2"` \| `"1MiB"` \| `"none"`) | `pow2` |
| Compression ratio side-channel | GPG compression off (`-z 0`), so the ciphertext size depends only on the padded bucket. The trade-off is a bigger vault; optional zstd *before* padding could come later | on |
| Inner commits leaking via outer | Never copied; outer is fully generic | on |

### What can NOT be hidden (residual leaks)

| Still visible on GitHub | Why / possible mitigation |
| :--- | :--- |
| **Number of recipients** | One header packet each. Optional later: `decoys = N`, extra throwaway recipient keys to round the count up. |
| Cipher/algorithm family (e.g. ECDH) | Part of the OpenPGP format. |
| Approximate size (bucket) | Reduced by padding, not eliminated. |
| Number and timing of pushes | GitHub logs push events, whatever the commit dates say. |
| The GitHub account and repo name | Your choice: use a neutral repo name, or a dedicated account / deploy key. |

## 6. CLI

| Command | Behavior |
| :--- | :--- |
| `crygpit init <path> [--remote URL] [--member FPR...]` | Creates `<path>.crypt/` and moves `<path>` into it. `git init`s inner if needed and writes default ignores to inner `.git/info/exclude`. Creates the meta with yourself as first member. Sets up outer repo + remote, does a first push. |
| `crygpit push [-m MSG]` | Inner auto-commit if dirty (`MSG` or `crygpit: snapshot <ts>`), then pack → pad → encrypt to all members. Skips if the plaintext hash is unchanged. Outer generic commit, then push. |
| `crygpit clone <remote> [dest]` | Clones, decrypts (gpg tries all your secret keys), shows the members and imports their public keys after confirmation (`--yes` to skip). Extracts `project/` and caches the meta. |
| `crygpit pull` | Outer pull, then decrypt to a temp dir. Inner auto-commits local work, then `git fetch <tmp>` and fast-forwards or merges. Updates the meta cache and imports new member keys (with confirmation). Aborts on conflict. |
| `crygpit ls` / `extract <file> [-o dir]` | Streamed decrypt; nothing written to disk except the requested file. |
| `crygpit status` | Inner dirty? Changed since push? Outer ahead/behind? Any member keys missing or expired? |
| `crygpit member add/rm/ls` | §4 |
| `crygpit unwrap` | Moves `project/` back out next to `project.crypt/`. |

## 7. Ignore Rules (builds / dependencies)

These defaults are written at `init` into the inner `project/.git/info/exclude`. Your tracked `.gitignore` stays untouched, and the excludes travel inside the vault.
```
node_modules/ target/ dist/ build/ out/ .next/ .nuxt/ .venv/ venv/
__pycache__/ *.pyc .tox/ .mypy_cache/ .pytest_cache/ vendor/ .gradle/
.idea/ .vscode/ *.log .DS_Store
```
On top of these come the project's `.gitignore` and `config.toml: extra_ignore`. The same rules apply to the inner auto-commit **and** the tar walk. `project/.git/` is always included.

## 8. Pipelines

**Push:**
```
build tar stream:  .crygpit-meta/  +  ignore::Walk(project/, sorted)  +  .crygpit-pad
   └─► Tee ─┬─► Sha256 (excluding pad)          → change detection (.crygpit/state.toml)
            └─► gpg --batch --status-fd 3 -e --throw-keyids -r ... -o vault.gpg.tmp
rename vault.gpg.tmp → vault.gpg   (only if gpg status says success)
```
- Normalized tar headers (uid/gid 0, empty uname/gname, sorted order) keep the hash stable and avoid leaking local usernames to members.
- The pad size is computed from the uncompressed tar size, rounded up to the bucket. GPG compression is disabled (`-z 0`), so the padded size maps directly to the ciphertext size.

**Unpack:** `gpg -d` → `tar::Archive`. Rejects absolute paths, `..`, symlinks/hardlinks escaping the target, and unexpected top-level entries.

> [!IMPORTANT]
> **GPG gotcha (verified):** with `--throw-keyids`, `gpg -d` **exits with code 2 even on success**, because it first tries non-matching keys. Crygpit must decide success by parsing `--status-fd` (`DECRYPTION_OKAY` + `GOODMDC`/AEAD OK, and no `DECRYPTION_FAILED`), **not** the exit code.

## 9. Architecture

Crygpit shells out to `gpg` and `git`, so it works with your keyring, agent, pinentry, YubiKey and SSH setup. Both sit behind traits (`Crypto`, `Vcs`), so native backends can be added later.

Crates: `clap`, `serde`, `toml`, `tar`, `ignore`, `sha2`, `rand` (padding), `tempfile`, `anyhow`, `thiserror`, `chrono`; dev: `assert_cmd`, `predicates`.

```
src/
├── main.rs  cli.rs
├── config.rs        meta config + root discovery
├── members.rs       members.toml, key import/export, validation
├── state.rs         local state + lock
├── layout.rs        init move / unwrap
├── ignore_rules.rs
├── pack.rs          meta + walk + pad → tar → tee(hash, gpg)
├── unpack.rs        gpg → tar (traversal guard), list, single extract
├── gpg.rs           Crypto trait, GnuPG impl, status-fd parser
├── git.rs           Vcs trait, git CLI impl, anonymized outer commits
└── commands/        init push clone pull ls extract status member unwrap
tests/e2e.rs
```

## 10. Safety

- `init` refuses if `<path>.crypt` exists, the path is nested in another `.crypt`, the inner repo has a remote (unless `--allow-remote`), or the move would cross filesystems.
- A lock file prevents concurrent push/pull.
- The outer repo never contains plaintext (allow-list `.gitignore`, plus a pre-commit check that the staged files are exactly `{.gitignore, vault.gpg}`).
- Atomic vault write (tmp + rename).

## 11. Test Plan (`tests/e2e.rs`)

Each test uses a temp `GNUPGHOME`, keys for Alice, Bob and Carol generated with `--quick-gen-key` (no passphrase), and a local bare repo standing in for GitHub.

1. `init`: layout created. The bare remote contains exactly `.gitignore` + `vault.gpg`.
2. Metadata: `gpg --list-packets` with an empty keyring shows only `keyid 0000000000000000`. The outer `git log` has a generic author, message and date.
3. Padding: vault sizes for small payloads fall into the expected bucket.
4. Ignores: `node_modules/` and `target/` are absent from `ls`.
5. Auto-commit: dirty inner → inner commit + outer commit. No change → push skipped.
6. Multi-member: Alice adds Bob and pushes. Bob clones with only his key, sees the members and Alice's history, commits and pushes. Alice pulls and fast-forwards.
7. Removal: Alice removes Carol and pushes. Carol can't decrypt HEAD but can still decrypt the previous commit (documents the caveat).
8. GPG rc=2 case: decrypt with `--throw-keyids` and multiple local secret keys succeeds via status-fd.
9. Security: a crafted `../evil` entry is rejected.
10. `unwrap` restores the original location.

## 12. Toolchain

A stable Rust toolchain exists at `~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/`, but `cargo` is not on PATH. Fix PATH/rustup, or the build will call cargo by its full path.
