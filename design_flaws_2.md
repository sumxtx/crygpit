## Real flaws

### 1. Concurrent member changes can't be merged
`members.toml` sits in the vault, not in inner git, so nothing merges it. Say Alice adds Dave while Bob removes Carol. Bob's push retries, merges inner history, and then rebuilds the vault with **his** `members.toml`, which drops Dave. There's also no rule for refusal: if Alice rejects Bob's change, her view and Bob's view of the membership split, and nothing reconciles them.

**Fix:** turn membership into an **append-only log of signed events**:
```
.crygpit-meta/members.log   one entry per change: {seq, op: add|remove|role, fpr, by, at, sig}
```
- The current members are computed by replaying the log. Two concurrent logs merge by taking the union of their events, ordered by `(seq, by)`.
- **Roles:** `owner` and `writer`. Only events signed by an owner can change membership. Writers' membership edits are rejected automatically, so there's no prompt to click through without reading.
- This also gives a full audit history for free.

### 2. Keys change over time, and that isn't handled
- **Expiry or renewal:** when Alice extends her key's expiry or rotates her encryption subkey, the new key material has to reach everyone. Otherwise others' pushes start failing, or keep encrypting to an old subkey. **Fix:** on pull, accept updated `keys/<fpr>.asc` only for an already-pinned fingerprint, when it's validly self-signed, and merge it into the project keyring.
- **Verifying a new member's first push:** gpg checks the signature during decryption, but a new member's public key may only exist inside the payload. **Fix:** decrypt once to read the keys, add them to the project keyring, then decrypt again to verify. Only signers already pinned in `trust.toml` count.
- **Lost key means lost project:** if a solo user loses their private key, the vault can never be opened again. **Fix:** `init` suggests adding a **recovery key** (an offline backup key) as an owner, and `doctor` warns if there's only one owner key.

### 3. A new member can be shown an old vault
The rollback check only protects people who have already pulled. When Dave clones for the first time, an attacker with GitHub access could serve him an **older** valid vault from before Mallory was removed. Dave would then trust Mallory and encrypt to her.

**Fix: invite tokens.** `crygpit member add` prints a token. Dave runs `crygpit clone <remote> --invite <token>`, and the clone must reach at least the vault the token describes. The token contains:
- the remote URL
- the latest counter (`seq`) and the vault hash
- the inviter's fingerprint

This replaces `--expect-signer`.

### 4. Branch changes don't carry over
- **Deleted branches:** a branch missing from the bundle looks the same as one that was never there, so deletions never reach other members and deleted branches come back.
- **Rebased or force-pushed branches:** another member's rebase gets merged back in, which revives the commits that were rewritten away.
- **Private branches:** every local branch is shared with everyone, including experiments you wanted to keep local.

**Fix:**
- Config `sync_refs` chooses what is shared (default `refs/heads/*` and `refs/tags/*`), with local-only exclusions.
- The vault records deleted branches as "tombstones" in its metadata.
- A non-fast-forward update is treated as a rewrite: it is never merged automatically, and the incoming version is kept for you to decide.

### 5. Auto-commit can put things in permanently
`git add -A` will pick up a forgotten 2 GB dataset or a `.env` file. Once pushed, it sits in every old vault in the outer history and in every member's clone, and can't really be removed.

**Fix:**
- Before an auto-commit, show the new untracked files.
- Ask for confirmation above a size limit (for example, any file over 10 MB, or more than 50 MB in total).
- Optionally block secret-looking patterns (`*.pem`, `id_*`, `.env*`) unless confirmed.

## Gaps in the spec
- **Old vault files:** say that `vault/` keeps only the **latest** full vault file (older ones are removed from the folder), with old ones remaining in outer git history.
- **What `prev_hash` hashes:** define it as the SHA-256 of the previous vault's **decrypted tar**, so it ties to the signed content and not the random ciphertext.
- **Push merging others' work:** `push` can silently merge other people's work into your working tree. Add `push --no-merge`, which fails if you're behind, for people who want to review with `pull` first.
- **GitHub access vs. crypto membership:** removing someone as a member doesn't remove their GitHub push access, so they can still delete or hide new pushes. `member rm` should remind you to remove them as a GitHub collaborator too.
- **Plaintext on your own disk:** the inner repo and temporary files are unencrypted locally. State that this is out of scope and recommend disk encryption.

---