# Implementation Plan (v7, Rust): Crygpit — Zero-Metadata Encrypted Mirrors

> Supersedes v6. It applies all fixes from `design_flaws_1.md` and `design_flaws_2.md`, including the "gaps in the spec".
> Changes vs v6 are marked **[v7]**.

---

## 0. Goal, Scope, Threat Model

### 0.1 Goal
GitHub, and anyone who can read or push to the outer repo, learns **only** that an encrypted blob exists and when it changes. Only members can see the history, files, branch names, contributors, member keys, roles and config.

### 0.2 Adversaries

| Adversary | Capabilities | Must NOT be able to |
| :--- | :--- | :--- |
| Public reader / GitHub | Read outer repo, see push events | Learn content, names, members, key IDs, signer |
| Outsider with outer push access | Replace, delete or re-upload blobs | Get members to accept forged, old or foreign vaults, or add a recipient |
| Malicious **writer** | Push valid segments | Change membership, run code on others' machines, silently rewrite shared history |
| Malicious **owner** | Change membership | Backdate events, or hide membership changes from other members |
| Removed member | Keep old clones, may keep GitHub access | Read anything pushed after removal, or get a segment accepted |
| New member (Dave) | Clone for the first time | Be tricked into an old or forked state when holding an invite token |

### 0.3 Out of scope (stated explicitly) **[v7]**
- **Plaintext on your own disk.** The inner repo, temporary files and swap are unencrypted locally. Use full-disk encryption. Crygpit minimizes temp plaintext (tmpfs, 0700, cleanup on exit and signals) but doesn't protect a compromised machine.
- **Freeze attacks.** An attacker can hide new pushes from you. Mitigated only by out-of-band comparison (`status` shows seq, hash and date).
- **Revoking access to old segments.** Anyone who once had access keeps it for those versions.
- **Phase 1 doesn't support:** git submodules, git LFS objects (pointer files are synced, LFS content is not), or files over the guard limits without confirmation.

---

## 1. Local Layout

`crygpit init ~/code/project` →

```
~/code/project.crypt/
├── .git/                    OUTER repo → GitHub. Linear, never merged, never user-signed.
├── .gitignore           ✔   allow-list
├── vault/               ✔
│   └── 000042.gpg       ✔   exactly ONE file in the tree in phase 1: the latest full segment [v7]
├── .crygpit/                LOCAL only (ignored), mode 0700
│   ├── local.toml           signing key, vault dir name, sync excludes, guard overrides, prefs
│   ├── trust.toml           project_id, genesis fpr, last accepted (seq, hash, log_head)
│   ├── state.toml           last published refs map, fingerprint, pending member events
│   ├── keyring.kbx          project-local PUBLIC keyring (members' keys)
│   ├── events.pending       member events signed locally but not yet pushed
│   ├── lock                 PID + timestamp
│   └── init.journal         only during/after a failed init
└── project/                 INNER repo, plaintext, NO remote, ignored by outer
    ├── .git/
    └── ...
```

Outer `.gitignore` (the vault dir name is configurable, default `vault`):
```
*
!.gitignore
!vault/
!vault/*.gpg
```

**[v7] Single latest file:** each push `git rm`s the previous `vault/*.gpg` and adds the new one in the same outer commit. Old segments exist only in outer git history. `clone` reads the single file in the tree.

---

## 2. Segment Format

### 2.1 Envelope
```
vault/NNNNNN.gpg  =  gpg --sign --encrypt --throw-keyids -z 0  ( segment.tar )
```
- The signature is inside the encryption, so the signer is hidden from GitHub.
- `NNNNNN` = `seq`, zero-padded to 6 digits (7+ digits allowed after 999999).

### 2.2 Plaintext tar (`segment.tar`)
The tar is deterministic: entries in this exact order, `uid=gid=0`, empty uname/gname, `mtime=0`, mode 0644, ustar format.

```
segment.tar
├── meta.toml          envelope metadata (§2.3)
├── members.log        signed, linear membership log, JSON Lines (§4)
├── keys/<FPR>.asc     current armored public key of every active member, one key per file
├── config.toml        shared project config (§2.5)
├── refs.toml          synced ref tips + tombstones (§6)
├── repo.bundle        git bundle of exactly the refs in refs.toml
└── pad                random bytes, Padmé-sized (§2.6). Always the last entry.
```

### 2.3 `meta.toml`
```toml
format         = 1
crygpit        = "0.1.0"
project_id     = "b3c1…"              # 128-bit random hex, created at genesis [v7]
seq            = 42
prev_hash      = "sha256:…"           # segment_hash of seq 41 (§2.4) [v7]
history        = [[1,"sha256:…"], [2,"sha256:…"], …, [41,"sha256:…"]]   # ancestry list [v7]
log_head       = { idx = 7, id = "sha256:…" }                        # last event in members.log
kind           = "full"               # "incremental" reserved for phase 2
bundle_sha256  = "…"
refs_sha256    = "…"
default_branch = "main"
created_at     = "2026-10-04T08:00:00Z"   # real time, safe because it's inside the encryption
```

### 2.4 Segment hash definition **[v7]**
```
segment_hash = "sha256:" + hex(SHA-256(segment.tar bytes, including pad))
```
This is the hash of the **decrypted, signed plaintext**, not the ciphertext (which is randomized). Because `pad` is inside the tar, the hash is unique per push even if the content repeats.

### 2.5 `config.toml` (shared)
```toml
name          = "project"
date_mode     = "fixed"         # fixed | day | real  (outer commit dates)
pad           = "padme"         # padme | none
sync_include  = ["refs/heads/*", "refs/tags/*"]
guard = { max_file_mb = 10, max_total_mb = 50, secret_patterns = ["*.pem","*.key","id_rsa*","id_ed25519*","id_ecdsa*","*.p12","*.pfx",".env",".env.*","*.kdbx","credentials*.json"] }
```
Changing the shared config requires **owner** role (§4.4).

### 2.6 Padding (Padmé)
```
L  = size of tar without pad entry (+512 header +1024 EOF blocks)
E  = floor(log2(L));  S = floor(log2(E)) + 1
z  = E - S;           mask = (1 << z) - 1
target = (L + mask) & !mask
pad data length = target - L, rounded to 512-byte blocks (min 0)
```
Overhead is at most ~12%. The ciphertext adds a near-constant overhead (recipient packets + signature), so the observable size is approximately Padmé-bucketed.

### 2.7 Size guard (phase 1)
If the encrypted output exceeds **95 MB**, push aborts with `E_TOO_LARGE`, pointing to the phase 2 features (§15).

---

## 3. Trust Anchors & Verification

### 3.1 Genesis and `project_id` **[v7]**
`init` creates the first event `genesis{project_id, founder_fpr}`. Every segment's `meta.project_id` and every event's `project_id` must equal the pinned value. This blocks **cross-project substitution**, where an attacker replaces the vault with another project's valid vault encrypted to the same people.

### 3.2 `trust.toml` (local)
```toml
project_id   = "b3c1…"
genesis_fpr  = "ABCD…"       # founder; pinned via invite token or TOFU
genesis_id   = "sha256:…"    # id of the genesis event
last_seq     = 42
last_hash    = "sha256:…"
last_log     = { idx = 7, id = "sha256:…" }
accepted_at  = "2026-10-04T08:00:00Z"
```

### 3.3 Segment verification algorithm
Input: ciphertext `C`. Output: an accepted segment, or `E_VERIFY` (exit 3).

1. **Decrypt pass 1** to tmpfs: `gpg --status-fd` (§9.2). Requires `DECRYPTION_OKAY` and integrity OK (`GOODMDC`, or AEAD with no `DECRYPTION_FAILED`). **The exit code is ignored**; with `--throw-keyids` it is 2 even on success.
2. Parse the tar strictly. The entry set and order must be exactly as in §2.2, with no other paths, no links, and no absolute or `..` paths. Each entry has a size limit (bundle: unlimited up to the file size; others ≤ 16 MiB).
3. **Key material:** validate each `keys/<FPR>.asc` (§5.1), then import valid ones into the project keyring.
4. **Pass 2 (only if pass 1 reported `NO_PUBKEY` for the signer):** decrypt again now that the keys are imported. Signature status needs `GOODSIG` + `VALIDSIG`. Reject `BADSIG`, `ERRSIG`, `REVKEYSIG`, missing signature, or still `NO_PUBKEY`. `EXPKEYSIG`: accept only if the key was valid at the signature time **and** the user confirms (`--accept-expired`).
5. `meta.project_id == trust.project_id`, `meta.format` is supported, and `bundle_sha256` and `refs_sha256` match.
6. **Membership log** (§4.5): replay from genesis. The genesis id must equal `trust.genesis_id`. Every event signature must be valid and every event authorized. The prefix rule: events `0..=trust.last_log.idx` must be byte-identical to the previously accepted log.
7. **Signer authorization:** the signer's primary fpr (last field of `VALIDSIG`) must have role `owner` or `writer` in the replayed state at `log_head`.
8. **Ancestry / rollback:** `meta.seq > trust.last_seq`, and `meta.history` must contain `[trust.last_seq, trust.last_hash]`. If `meta.seq == trust.last_seq + 1`, also `meta.prev_hash == trust.last_hash`.
9. `git bundle verify` + fetch with `transfer.fsckObjects=true` (§6.4).
10. Only then update `trust.toml` (atomic write).

---

## 4. Membership: Signed Linear Log **[v7]**

### 4.1 Why linear (refinement of flaw-1 fix)
A union-merge of concurrent logs would let a removed owner **backdate** events (craft an event ordered before their removal). Instead:
- The log is a **strict hash chain**: each event references `prev` = the id of the previous event.
- The outer repo is linear and push retries after fetching. So when two people change membership concurrently, the loser's **unpublished** events are **rebased**: re-created on the new head and re-signed by their own author, then re-checked for authorization. Published events are never touched.
- Backdating is impossible: a new event can only extend the current head, and the prefix rule (§3.3 step 6) rejects any rewrite of accepted history.

### 4.2 Event format (`members.log`, one JSON object per line)
```json
{"v":1,"idx":5,"prev":"sha256:…","project_id":"b3c1…",
 "op":"add","subject":"FPR_DAVE","role":"writer","label":"dave@example.com",
 "by":"FPR_ALICE","at":"2026-10-04T08:00:00Z",
 "sig":"<base64 of armored detached signature over the canonical bytes>"}
```
- **Canonical bytes:** the JSON with the `sig` field removed, keys sorted, no whitespace, UTF-8 (RFC 8785 JCS subset).
- **Event id:** `"sha256:" + hex(SHA-256(canonical bytes))`.
- `idx` starts at 0 (genesis) and increments by 1. `prev` of genesis = `null`.

### 4.3 Operations

| op | Fields | Meaning |
| :--- | :--- | :--- |
| `genesis` | `subject` = founder, `role` = owner | Creates the project; `project_id` is defined here |
| `add` | `subject`, `role`, `label` | Adds a member (the key must be present in `keys/`) |
| `remove` | `subject`, `reason?` | Removes a member |
| `role` | `subject`, `role` | Changes a role |
| `leave` | `subject` = `by` | Self-removal |
| `config` | `config_sha256` | Approves a new `config.toml` (owner only) |

Roles: **owner** (manage members and config, push), **writer** (push), **reader** (decrypt only; segments signed by readers are rejected).

### 4.4 Authorization rules (evaluated during replay, in order)
1. `genesis` is valid only at idx 0, with `by == subject` and `role == owner`.
2. `add`, `remove`, `role` and `config` need `by` to be an active **owner** at that point.
3. `leave` needs `by == subject` and `by` to be active.
4. **Last-owner protection:** an event that would leave zero active owners is invalid.
5. `add` of an already active fpr is invalid; re-adding a removed fpr is allowed (a new membership).
6. Any invalid event makes the **whole segment invalid** (`E_VERIFY`). An honest client never produces invalid events, because the rebase step (§4.1) re-checks authorization before re-signing and drops its own invalid pending events with an error.
7. The segment's `config.toml` hash must equal the latest `config` event's `config_sha256` (or the genesis default).

### 4.5 Replay output
`MemberState { members: Map<Fpr, {role, label, added_at, added_by}>, removed: Vec<…>, owners: Set<Fpr>, config_sha256 }`.
`recipients = members with any role` (owner/writer/reader) ∪ {self}. `self` must be in the set, otherwise push aborts with "you are not a member".

### 4.6 Notifications
On pull, membership changes since `trust.last_log` are **printed** (who added or removed whom, and the role). No prompt is needed, because owner signatures authorize them. Setting `confirm_member_changes = true` in `local.toml` turns these into prompts.

### 4.7 Member removal reminder **[v7]**
`member rm` prints:
> Removed from encryption. They can still push to or delete from the GitHub repo until you remove them as a collaborator or revoke their deploy key.

`doctor` repeats this for recently removed members.

---

## 5. Key Lifecycle **[v7]**

### 5.1 Key file validation (`keys/<FPR>.asc`)
`gpg --show-keys --with-colons --import-options show-only` must show:
- exactly one `pub` record, whose fingerprint equals `<FPR>` (the filename) and an **active member** fpr;
- valid self-signatures;
- at least one usable encryption subkey (not expired, not revoked) for active members. Otherwise warn and skip that member as a recipient, and warn the owner.

If validation fails, the key isn't imported. If it belongs to the segment signer, verification fails.

### 5.2 Updates (expiry extension, subkey rotation, revocation)
- On push, crygpit exports the **current** public key of each member from your keyrings (project + default). It uses whichever copy is newest: the one with the latest self-signature.
- On pull, a key file for an already-known fpr is imported with `--import-options merge-only,import-clean`. New self-signatures and subkeys merge in; a different primary key can't.
- **Revoked primary key:** the member is excluded from recipients immediately, with a warning: "owner should run `crygpit member rm`".
- **Rotating to a new primary key:** this is done as two log events, `add` (new fpr) then `remove` (old fpr), both signed by an owner. A member can't do this on their own unless they are an owner.

### 5.3 Recovery key
- `init --recovery-key <FPR|file>` adds an offline key as a second **owner** in the genesis segment.
- Without one, `init` asks interactively ("Add a recovery key? Without one, losing your key loses the project.").
- `doctor` warns when `owners.len() == 1`.

---

## 6. Ref Synchronization **[v7]**

### 6.1 What is synced
- Shared include: `config.sync_include` (default `refs/heads/*`, `refs/tags/*`).
- Local exclude (never published): `local.toml: sync_exclude` (default `["refs/heads/local/*", "refs/heads/wip/*"]`).
- Never synced: `refs/crygpit/*`, `refs/stash`, `refs/remotes/*`, notes, `HEAD` (but `meta.default_branch` records the branch).

### 6.2 `refs.toml`
```toml
[refs]
"refs/heads/main"    = "9f2c…"
"refs/heads/feat-x"  = "11ab…"
"refs/tags/v1.0"     = "77de…"

[tombstones]
"refs/heads/old-exp" = { last = "c0ff…", by = "FPR_ALICE", seq = 40 }
```

### 6.3 Baseline: `state.toml.published`
The refs map of the **last segment you accepted or published**. It's used to tell "I deleted it" apart from "I never had it", and "they rewrote it" apart from "they extended it".

### 6.4 Bundle import
```
git bundle verify <tmp>/repo.bundle
git -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
    fetch --no-tags --no-write-fetch-head <tmp>/repo.bundle \
    '+refs/heads/*:refs/crygpit/incoming/heads/*' '+refs/tags/*:refs/crygpit/incoming/tags/*'
```
Then `refs.toml` must exactly match the fetched incoming refs. Otherwise `E_VERIFY`.

### 6.5 Incoming reconciliation (for each ref name `r`)
Notation: `L` = local tip, `I` = incoming tip, `B` = baseline (`published[r]`), `T` = incoming tombstone.

| Case | Condition | Action |
| :--- | :--- | :--- |
| New | `L` none, `B` none, `I` set | Create `r = I` |
| Locally deleted | `L` none, `B` set, `I` set | Keep it deleted if `I == B` (our deletion gets published). If `I ≠ B`, others moved it: recreate it and warn. |
| Same | `L == I` | Nothing |
| Fast-forward | `I` descends from `L` | Current branch: `git merge --ff-only`. Others: `update-ref r I L`. |
| We're ahead | `L` descends from `I` | Nothing (published on our next push) |
| Diverged, normal | `I` descends from `B` and `L` descends from `B` | Current branch: `git merge --no-edit refs/crygpit/incoming/...`. On conflict, stop with `E_CONFLICT`. Others: keep `refs/crygpit/incoming/<r>` and report. |
| **Rewritten remotely** | `B` set and `I` **not** a descendant of `B` | Never merged. Saved as `refs/crygpit/rewritten/<r>` and reported. Resolve with `crygpit resolve <r> --theirs\|--mine`. |
| Tombstone | `T` set, `L == T.last` | Delete local `r` |
| Tombstone, but we have work | `T` set, `L ≠ T.last` | Keep `r` and warn. Our next push re-creates it and drops the tombstone. |
| Tag differs | `refs/tags/*`, `L ≠ I` | Keep local and warn. Tags are immutable. |

### 6.6 Outgoing (building `refs.toml` on push)
- `refs` = all local refs matching include and not exclude.
- New tombstone for `r` if `r ∈ published`, `r` doesn't exist locally, and `r` matches include.
- Incoming tombstones are carried forward until the ref is re-created. Tombstones older than 1000 segments may be dropped (phase 2).
- **Local rewrite detection:** if `published[r]` exists and the local `r` doesn't descend from it, push refuses for that ref (`E_REWRITE`) unless `--allow-rewrite <r>` is given (like `--force-with-lease`).
- Bundle: `git bundle create <tmp>/repo.bundle <all refs in refs.toml>`. An empty repo is handled by the auto-commit creating an initial commit (`--allow-empty` if there are no files).

---

## 7. Auto-commit Guard **[v7]**

Runs before every auto-commit in `push`, `pull` and pre-merge.

1. `git status --porcelain=v2 -z --untracked-files=all` lists new, modified and deleted files (inner excludes respected).
2. Sizes come from the files on disk.
3. **Triggers:**
   - any single new or modified file > `guard.max_file_mb`
   - total size of new and modified files > `guard.max_total_mb`
   - any path matching `guard.secret_patterns` (globset, case-insensitive basename and path match)
4. **Interactive:** print a table (path, size, reason) and the summary, then prompt `[y]es / [n]o / [e]dit excludes`.
5. **Non-interactive:** fail with `E_GUARD` unless `--allow-large` and/or `--allow-secrets` is given.
6. A one-line summary is always printed: `auto-commit: 12 files (+3 new), 184 KiB`.
7. `push --no-auto-commit` fails with `E_DIRTY` if the inner repo is dirty.

`local.toml` can loosen or tighten the shared guard **for this machine only**.

---

## 8. Commands — Detailed Flows

Global flags: `-C <path>`, `-y/--yes` (non-security prompts only), `-q`, `-v`, `--no-color`.
Root discovery walks up from the current directory to the folder containing `.crygpit/` and `vault/`.

### 8.1 `crygpit init <path> [--remote URL] [--member FPR[:role]]... [--recovery-key K] [--vault-dir D] [--allow-remote] [--yes]`
1. **Validate:**
   - `<path>` is a dir; `<path>.crypt` doesn't exist; `<path>` isn't inside a `.crypt`
   - same filesystem as its parent; inner git has no remotes (unless `--allow-remote`)
   - no submodules (warn and abort unless `--yes`)
   - gpg and git versions OK; the signing key can sign (test signature through the agent)
   - every `--member` key is valid (§5.1); the remote is reachable (`git ls-remote`) if given, and **empty**
2. Show the default excludes (§12) and the optional ones. Confirm or edit.
3. Recovery-key prompt (§5.3).
4. Create a sibling temp dir `<path>.crypt.tmp-<rand>` and start `init.journal`.
5. Outer skeleton: `git init`, `.gitignore`, `.crygpit/` (0700), `local.toml`, `keyring.kbx`.
6. `rename(<path>, tmp/project)` (journal: `moved`).
7. Inner: `git init` if needed, write `.git/info/exclude`, run the guard and auto-commit (initial commit).
8. Build the membership log: genesis, then the `add` for each member and recovery key (all signed by you).
9. Build and encrypt segment `seq=1` (`prev_hash = null`, `history = []`), then make the outer commit (§9.3).
10. `rename(tmp, <path>.crypt)` (journal: `committed`), then delete the journal.
11. If `--remote` was given: `git push -u origin HEAD:main`. A failure here gives a warning, not a rollback.
12. **On failure in steps 4–10:** reverse the journal (move the project back, delete the temp dir). `crygpit init --recover <path>.crypt.tmp-*` handles crashes.

### 8.2 `crygpit push [-m MSG] [--no-merge] [--no-auto-commit] [--allow-rewrite REF]... [--allow-large] [--allow-secrets]`
```
acquire lock
guard + auto-commit (unless --no-auto-commit)
for attempt in 1..=5:
    outer: git fetch origin
    if origin has a newer segment than trust.last_seq:
        if --no-merge: abort E_BEHIND "run `crygpit pull` first"   [v7]
        verify (§3.3) → reconcile refs (§6.5) → may stop with E_CONFLICT
        rebase pending member events onto new log head (§4.1); drop + report any now-unauthorized
    compute fingerprint = H(synced refs map, tombstones, log head incl. pending, config hash, key files)
    if fingerprint == state.fingerprint and no pending events: print "up to date"; exit 0
    check local rewrites (§6.6) → E_REWRITE unless allowed
    build segment seq = last_seq+1, prev_hash = last_hash, history = prev.history + [[last_seq,last_hash]]
    encrypt+sign → vault/NNNNNN.gpg.tmp → fsync → rename; git rm old vault file  [v7]
    outer commit (§9.3) on top of origin/main
    git push origin HEAD:main  (no force)
    if rejected (non-fast-forward): git reset --hard origin/main; continue
    success: trust ← this segment; state.published ← refs; state.fingerprint ← fp; clear pending; break
after 5 failures: E_REMOTE "remote busy"
release lock
```

### 8.3 `crygpit pull [--allow-large] [--allow-secrets]`
Lock → guard + auto-commit → `git fetch` → if newer: `git reset --hard origin/main` (outer has no local changes by construction) → verify → reconcile → update trust and state → print the membership changes and ref report.

### 8.4 `crygpit clone <remote> [dest] [--invite TOKEN] [--trust-on-first-use]` **[v7]**
1. `git clone <remote> <dest>` (default dest: `<repo-name>.crypt`).
2. Discover the vault dir from `.gitignore`; there must be exactly one `*.gpg` in it.
3. **With an invite token:**
   - Check that the token's `project_id`, `genesis_id` and `genesis_fpr` match what the decrypted segment says.
   - `meta.seq >= token.seq`, and `meta.history` contains `[token.seq, token.segment_hash]` (or the head equals it).
   - `log_head.idx >= token.log_idx`, and the event at `token.log_idx` has id `token.log_id`.
   - The invitee's own fpr is an active member.
4. **Without a token:** requires `--trust-on-first-use` or an interactive confirmation that shows the genesis fpr, owners, members, seq and `created_at`. A loud warning explains the rollback risk for new members.
5. Pin `trust.toml`, then do a full verification (§3.3) with this initial trust.
6. Create the inner repo: `git init`, then fetch the bundle into `refs/heads/*` and `refs/tags/*`, check out `default_branch`, and write the default excludes into `.git/info/exclude` from the shared config.
7. `state.published = refs`.

### 8.5 Member commands
| Command | Flow |
| :--- | :--- |
| `member add <key.asc\|FPR> [--role writer] [--label L]` | Owner only. Validate the key (§5.1), import it into the project keyring, sign an `add` event into `events.pending`. Takes effect on next push. |
| `member rm <FPR> [--reason R]` | Owner only. Pending `remove` event, plus the collaborator reminder (§4.7). |
| `member role <FPR> <role>` | Owner only. Pending `role` event. |
| `member leave` | Pending `leave` event. After the push you can no longer decrypt future segments. |
| `member ls [--log]` | Active members and roles. `--log` shows the full signed history. |
| `invite <FPR>` | Requires a published segment in which `<FPR>` is active. Prints the token (§8.6). |

### 8.6 Invite token **[v7]**
```
crygpit1:<base64url(JSON)>
{ "remote": "git@github.com:me/x.git", "project_id": "…", "genesis_id": "sha256:…",
  "genesis_fpr": "…", "seq": 43, "segment_hash": "sha256:…",
  "log_idx": 8, "log_id": "sha256:…", "inviter": "FPR_ALICE", "invitee": "FPR_DAVE" }
```
Send it over a trusted channel (Signal, in person). It holds no secrets, but it is the trust anchor.

### 8.7 Other commands
| Command | Flow |
| :--- | :--- |
| `resolve <ref> --theirs\|--mine` | Settles rewritten or diverged refs saved under `refs/crygpit/*`. |
| `ls [--ref R]` | Verify the latest segment, unpack the bundle into a temp bare repo (tmpfs, 0700), run `git ls-tree -r --name-only R`, clean up. |
| `extract <path> [--ref R] [-o DIR]` | Same as `ls`, then `git show R:path` into the output. Refuses to overwrite without `--force`. |
| `status` | Inner dirty/unpushed and guard preview; outer ahead/behind; `last_seq`, hash prefix, `accepted_at`; pending events; key health (expiring within 30 days); single-owner warning. |
| `doctor` | Tool versions; whether the agent can sign without a TTY; project keyring readable; recipient validity; remote reachable; outer config safe (§9.3); last segment size vs limit; recently removed members reminder. |
| `unwrap [--force]` | Requires a clean inner repo and nothing unpushed (or `--force`). Moves `project/` back next to `.crypt`. |

---

## 9. External Tool Invocations

### 9.1 Common
- All child processes get an explicit environment: `LC_ALL=C`, `GIT_TERMINAL_PROMPT=0` for outer fetches in non-interactive mode.
- stdout and stderr are captured, and the status fd is read on a separate thread (pipe on fd 3) to avoid deadlocks.

### 9.2 gpg
```
# sign + encrypt (push)
gpg --batch --status-fd 3 --no-auto-key-locate \
    --keyring <crypt>/.crygpit/keyring.kbx --trust-model always \
    --throw-keyids -z 0 --local-user <SIGN_FPR> \
    --sign --encrypt  -r <FPR1> -r <FPR2> ... \
    --output vault/NNNNNN.gpg.tmp  -          (stdin = segment.tar stream)

# decrypt + verify
gpg --batch --status-fd 3 --keyring <proj> --trust-model always \
    --decrypt --output <tmpfs>/segment.tar  vault/NNNNNN.gpg

# event signature
gpg --batch --status-fd 3 --local-user <FPR> --detach-sign --armor   (stdin = canonical bytes)
gpg --batch --status-fd 3 --keyring <proj> --trust-model always --verify <sig> -

# key inspection / import
gpg --show-keys --with-colons <file.asc>
gpg --no-default-keyring --keyring <proj> --import-options import-clean[,merge-only] --import <file.asc>
gpg --keyring <proj> --export --armor <FPR>      (also checks the default keyring)
```
- Recipients are full primary fingerprints without `!`, so gpg picks the current encryption subkey.
- `--batch` still allows pinentry through the agent. Non-interactive failures are caught by `doctor` and reported as `E_GPG`.

**Status-fd verdict parser** (unit-tested with recorded transcripts):
`DECRYPTION_OKAY`, `DECRYPTION_FAILED`, `GOODMDC`, `BEGIN_DECRYPTION`/`END_DECRYPTION`, `GOODSIG`, `VALIDSIG` (field 10 = primary fpr), `BADSIG`, `ERRSIG`, `EXPSIG`, `EXPKEYSIG`, `REVKEYSIG`, `NO_PUBKEY`, `NO_SECKEY`, `KEYEXPIRED`, `KEYREVOKED`, `INV_RECP`, `FAILURE`.

### 9.3 git (outer repo) **[v7 hardening]**
Every outer git command runs with:
```
-c core.hooksPath=/dev/null -c commit.gpgsign=false -c tag.gpgsign=false
-c user.name=crygpit -c user.email=crygpit@invalid
GIT_AUTHOR_NAME=crygpit GIT_AUTHOR_EMAIL=crygpit@invalid
GIT_COMMITTER_NAME=crygpit GIT_COMMITTER_EMAIL=crygpit@invalid
GIT_AUTHOR_DATE / GIT_COMMITTER_DATE = per date_mode (fixed: 2000-01-01T00:00:00Z)
commit message: "update"
```
This prevents your global `commit.gpgsign` from leaking your identity through a signed outer commit, and stops global hooks from running.

### 9.4 git (inner repo)
- Your own hooks and config apply (it's your repo).
- Bundle import always uses fsck (§6.4).
- Merges use `--no-edit`. The auto-commit message is `MSG` or `crygpit: snapshot <ISO ts>`.

---

## 10. Concurrency, Atomicity, Cleanup

| Concern | Mechanism |
| :--- | :--- |
| Two crygpit processes | `.crygpit/lock` (O_EXCL create) with PID + start time. A stale lock (PID dead) is broken with a warning. |
| Two members pushing | §8.2 loop: fetch, verify, merge, rebase events, rebuild, push without force, retry ≤ 5. |
| Partial vault write | `.tmp` → fsync → rename |
| Partial state writes | All TOML/JSON written through `tmp` + fsync + rename |
| Temp plaintext | `$XDG_RUNTIME_DIR/crygpit-<rand>` (falls back to `.crygpit/tmp`, 0700). Removed by a `Drop` guard plus a SIGINT/SIGTERM handler. |
| Push fails after outer commit | The next push or pull resets the outer repo to origin before rebuilding. The local outer repo is disposable by design. |

---

## 11. Metadata Hardening Summary

| Leak | Mitigation |
| :--- | :--- |
| Recipient key IDs | `--throw-keyids` (always) |
| Signer | Signature inside the encryption |
| Members, roles, config, branch names, project name | Inside the payload only |
| Outer author, email, signature, message, date | Fixed values (§9.3) |
| Exact size | Padmé |
| Tool name | `--vault-dir` configurable |
| **Cannot hide** | Recipient count, OpenPGP algorithm family, size bucket, push count and timing, GitHub account and repo name |

---

## 12. Inner Ignore Defaults

Written to `project/.git/info/exclude` at init and clone, after confirmation. They affect **untracked** files only.
```
# default
node_modules/  target/  dist/  .next/  .nuxt/  .venv/  venv/  __pycache__/
*.pyc  .tox/  .mypy_cache/  .pytest_cache/  .gradle/  *.log  .DS_Store
# optional (offered, off by default)
build/  out/  vendor/  .vscode/  .idea/
```

---

## 13. Exit Codes

| Code | Name | Meaning |
| :- | :--- | :--- |
| 0 | OK | |
| 1 | E_GENERIC | Unexpected error |
| 2 | E_USAGE | Bad CLI usage |
| 3 | E_VERIFY | **Security**: decrypt, signature, membership, rollback or format check failed |
| 4 | E_CONFLICT | Inner merge conflict; resolve and re-run |
| 5 | E_REMOTE | Network or remote rejection after retries |
| 6 | E_GPG | gpg missing, key unusable, agent can't sign without a TTY |
| 7 | E_GUARD | Auto-commit guard blocked (large or secret files) |
| 8 | E_LOCKED | Another crygpit process is running |
| 9 | E_BEHIND | `--no-merge` and the remote is ahead |
| 10 | E_REWRITE | A local ref rewrite would be published without `--allow-rewrite` |
| 11 | E_DIRTY | `--no-auto-commit` with a dirty inner repo |
| 12 | E_TOO_LARGE | Segment exceeds 95 MB |

---

## 14. Architecture

### 14.1 Crates
`clap` (derive), `serde`, `serde_json`, `toml`, `tar`, `sha2`, `hex`, `base64`, `rand`, `globset`, `tempfile`, `anyhow`, `thiserror`, `chrono`, `ctrlc`, `nix` (flock/pid checks).
Dev: `assert_cmd`, `predicates`, `insta` (snapshot tests for status-fd transcripts).

### 14.2 Modules
```
src/
├── main.rs                 entry, exit-code mapping
├── cli.rs                  clap definitions
├── error.rs                CrygpitError → exit codes
├── paths.rs                root discovery, vault dir discovery, tmpfs dirs
├── fsutil.rs               atomic write, lock, fsync, Drop cleanup guard
├── config/
│   ├── shared.rs           config.toml
│   └── local.rs            local.toml
├── trust.rs                trust.toml + ancestry/rollback checks
├── state.rs                state.toml, fingerprint
├── crypto/
│   ├── mod.rs              Crypto trait
│   ├── gnupg.rs            GnuPG impl (encrypt/decrypt/sign/verify/import/export/show)
│   └── status.rs           status-fd parser + verdict types
├── vcs/
│   ├── mod.rs              Vcs trait
│   ├── outer.rs            anonymized outer ops
│   └── inner.rs            status, auto-commit, bundle, fetch, merge, ref ops
├── members/
│   ├── event.rs            Event, canonicalization, id, sign/verify
│   ├── log.rs              append, rebase pending, prefix check
│   └── replay.rs           authorization rules → MemberState
├── keys.rs                 key validation, merge, export
├── segment/
│   ├── build.rs            deterministic tar writer + Padmé
│   ├── parse.rs            strict tar reader
│   └── meta.rs             Meta, history
├── refsync.rs              outgoing refs/tombstones, incoming reconciliation table
├── guard.rs                auto-commit guard
├── invite.rs               token encode/decode/check
├── sync.rs                 push loop, pull
├── init.rs                 transactional init + recover, unwrap
└── commands/               one file per command (thin)
tests/
├── common/mod.rs           temp GNUPGHOME, key factory (Alice/Bob/Carol/Dave/Mallory/Recovery), bare remote
└── e2e_*.rs
```

### 14.3 Core types (sketch)
```rust
struct Fpr(String);                         // 40 hex, uppercase
enum Role { Owner, Writer, Reader }
enum Op { Genesis, Add{subject:Fpr, role:Role, label:String}, Remove{subject:Fpr}, RoleChange{subject:Fpr, role:Role}, Leave, Config{sha256:String} }
struct Event { v:u8, idx:u64, prev:Option<Hash>, project_id:ProjectId, op:Op, by:Fpr, at:DateTime<Utc>, sig:String }
struct Meta { format:u32, project_id:ProjectId, seq:u64, prev_hash:Option<Hash>, history:Vec<(u64,Hash)>, log_head:(u64,Hash), kind:Kind, bundle_sha256:String, refs_sha256:String, default_branch:String, created_at:DateTime<Utc> }
struct RefsFile { refs:BTreeMap<String,Oid>, tombstones:BTreeMap<String,Tombstone> }
struct Verdict { decrypted:bool, integrity:bool, signer_primary:Option<Fpr>, sig_status:SigStatus, missing_pubkey:Option<String> }
trait Crypto { fn encrypt_sign(&self, recipients:&[Fpr], signer:&Fpr, input:impl Read, out:&Path) -> Result<()>; fn decrypt(&self, input:&Path, out:&Path) -> Result<Verdict>; /* sign_detached, verify_detached, import, export, show */ }
```

---

## 15. Phase 2 (designed for, not built in phase 1)
- **Incremental segments:** `kind = "incremental"`, `base_seq`, bundle of the changes since the last published tips. The tree holds the latest full segment plus the incrementals after it. A full snapshot is made every N segments or when the incrementals add up to more than X% of a full one.
- **Chunking:** a segment is split into ≤ 32 MiB parts `NNNNNN.K.gpg`. Each part is signed and encrypted; the part hashes are listed in a small signed and encrypted index part.
- **`compact`:** new full segment; optional outer history rewrite (orphan + force push) with a coordination warning. `history` is truncated through a signed checkpoint.
- **Decoy recipients** to round up the recipient count.
- **Tombstone garbage collection.**

---

## 16. Milestones & Acceptance Criteria

| # | Milestone | Done when |
| :- | :--- | :--- |
| M0 | **Spikes** (§17) | All four answered, decisions recorded in `docs/spikes.md` |
| M1 | Skeleton: CLI, errors, paths, atomic fs, lock, tmpfs cleanup | `crygpit --help`; lock and cleanup unit tests pass |
| M2 | Crypto: gnupg wrapper + status parser | Encrypt/decrypt/sign/verify round-trip with a temp keyring; rc=2 case → verdict OK; recorded transcripts snapshot-tested |
| M3 | Segment build/parse + Padmé + hash | Deterministic tar (same input → same bytes before pad); strict parser rejects every malformed fixture |
| M4 | Membership log: events, canonicalization, replay, rebase | Property tests: random valid op sequences replay identically; all §4.4 violations rejected; backdating fixture rejected |
| M5 | Single-user flow: init (transactional), push, pull, clone (TOFU), ls, extract, unwrap | E2E tests 1–5, 17–20 pass |
| M6 | Multi-user: refsync, push loop, invite, keys lifecycle | E2E tests 6–16, 21–26 pass |
| M7 | Guard, doctor, status, polish | E2E 27–30 pass; `doctor` clean on a fresh setup |

---

## 17. Spikes (M0)
1. **Project keyring:** do `--keyring <kbx>` (in addition to the default) plus `--trust-model always` let gpg 2.4 encrypt to keys found only in the project keyring, verify signatures, and still use the default keyring's secret keys through the agent? Fallback: import members into the default keyring after confirmation.
2. **Status lines:** record the full status-fd transcripts for sign+encrypt and for decrypt+verify, with `--throw-keyids`, multiple local secret keys, a missing signer key, and an expired key.
3. **Bundles:** empty repo, tags-only, excluded refs, fsck rejection of a crafted object, and how big a bundle of a mid-size repo is.
4. **`--import-options merge-only`:** behavior for subkey rotation and expiry extension on an existing primary key.

---

## 18. Test Matrix

Each test uses a temp `GNUPGHOME`, keys for Alice, Bob, Carol, Dave, Mallory and Recovery (no passphrase), and local bare repos as remotes.

| # | Area | Scenario | Expected |
| :- | :--- | :--- | :--- |
| 1 | init | Basic | Layout created. Remote tree = `.gitignore` + one `vault/000001.gpg`. Project moved. |
| 2 | init | Failure injected after the move | Project restored, temp removed |
| 3 | init | Crash simulated (journal left behind) | `--recover` restores |
| 4 | metadata | Empty-keyring `--list-packets` | Only `keyid 0000000000000000`, no signer visible |
| 5 | metadata | Outer log, global `commit.gpgsign=true` set | Author/committer `crygpit`, fixed date, message `update`, **unsigned** |
| 6 | single file | Three pushes | The tree always holds exactly one `vault/*.gpg`; history holds 3 |
| 7 | multi | Alice adds Bob, pushes, invites | Bob clones with the token, sees history, pushes; Alice pulls (ff) |
| 8 | concurrency | Alice and Bob push from the same base | Second push retries, merges, succeeds; outer linear |
| 9 | concurrency | Alice adds Dave while Bob (owner) removes Carol | Both events end up in a linear log; final members = {Alice, Bob, Dave} |
| 10 | concurrency | Alice demotes Bob to writer while Bob adds Mallory | Bob's rebase drops his `add` as unauthorized and reports it |
| 11 | forgery | Mallory (outsider) pushes a vault encrypted to Alice, signed by Mallory | `E_VERIFY` |
| 12 | forgery | Writer Bob includes an `add Mallory` event signed by himself | `E_VERIFY` (unauthorized event) |
| 13 | forgery | Removed owner backdates an `add` before their removal | `E_VERIFY` (prefix/chain) |
| 14 | rollback | An old valid segment re-pushed as the newest | `E_VERIFY` (seq/history) |
| 15 | rollback | New member clones with a token, remote serves an older segment | `E_VERIFY` (token seq/hash) |
| 16 | substitution | Another project's valid vault, same recipients | `E_VERIFY` (`project_id`) |
| 17 | hooks | Bob's inner repo has a `post-checkout` hook | Hook absent on Alice's machine |
| 18 | ls/extract | List and extract a file at a ref | Correct; temp dir removed |
| 19 | change detect | `git status` only | "up to date" |
| 20 | unwrap | | Original location restored |
| 21 | keys | Bob extends expiry, pushes | Alice's keyring gets the new expiry; her pushes keep working |
| 22 | keys | Bob rotates his encryption subkey | The next segment from Alice is encrypted to the new subkey |
| 23 | keys | New member's first push, key only in payload | Two-pass verify succeeds |
| 24 | keys | Key file with an extra primary key or a mismatched fpr | Rejected |
| 25 | removal | Carol removed | Can't decrypt the new head; can decrypt the old (documented) |
| 26 | refs | Deleted branch, remote rewrite, tag change, local-only `wip/*` | Tombstone propagates; rewrite saved under `refs/crygpit/rewritten`; tag kept local; `wip/*` never in the bundle |
| 27 | guard | 20 MB untracked file | Interactive prompt; non-interactive `E_GUARD`; passes with `--allow-large` |
| 28 | guard | `.env` file | Blocked unless `--allow-secrets` |
| 29 | no-merge | Remote ahead + `push --no-merge` | `E_BEHIND` |
| 30 | size | Payload > 95 MB | `E_TOO_LARGE` |
| 31 | gpg rc | `--throw-keyids` + multiple local secret keys | Decrypt verdict OK despite rc=2 |
| 32 | recovery | Alice's key deleted, Recovery key used | Recovery can decrypt, push and remove Alice |

---

## 19. Residual Risks (accepted)
- **Freeze attack** (§0.3): detectable only out-of-band.
- **TOFU clone without a token:** the user is warned, and must opt in explicitly.
- **A malicious owner** has full power over membership. That's inherent; use the recovery key and few owners.
- **Removed members keep old versions.** Rotate secrets.
- **GitHub sees** the recipient count, size bucket and push timing.
- **Local plaintext** is out of scope; use disk encryption.

## 20. Prior Art
[git-remote-gcrypt](https://spwhitton.name/tech/code/git-remote-gcrypt/) does encrypted git remotes with gpg, multiple participants and hidden recipients. Review its manifest format and concurrency handling during M0. Crygpit adds:
- a signed membership log with roles
- invite tokens and rollback / substitution protection
- key lifecycle handling
- padding and an anonymized outer repo
- the `.crypt` wrapper workflow with guarded auto-commit.
