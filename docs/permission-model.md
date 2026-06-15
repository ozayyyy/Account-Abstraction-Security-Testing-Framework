# Permission model and threat analysis

## Components

| Component | What it is | Trust level |
| --- | --- | --- |
| Owner | The account holder's key. The root of trust for the account. | Fully trusted by the account |
| EntryPoint | `MinimalEntryPoint`. Calls `validateUserOp`, then executes the validated callData. | Trusted to call only after validation; it never invents operations |
| Validator | `SimpleValidator`. Answers one question: does this signature recover to the owner over this operation hash? | Trusted for signature checking only; it has no execution rights |
| Executor | A limited session key (e.g. a dapp session). May use the account, but only within its allowlist. | Partially trusted, scope-limited |
| Session-key validator | `SessionKeyValidator`. Holds per-key policy: expiry, spending limit, allowed target, revocation. The account consults it on every executor call when one is set. | Trusted for policy checks only; it cannot execute and cannot change account state |
| Delegated EOA | An externally owned account that signed an EIP-7702 authorisation to run an implementation's code as itself. | Trusted exactly as much as the implementation it delegated to — which may be nothing |
| Module | Code installed into the account. Once installed it is trusted to call `moduleExecute`. | Trusted once installed — installation is the gate |
| Target | An ordinary external contract (`Target.setValue` / `increment`). Holds no funds, no privileges. | Untrusted, harmless |

## Expected permission matrix

"Allowed" means the call must succeed. "Blocked" means it must revert.
"—" means the path does not apply.

| Action | Owner | EntryPoint (validated op) | Executor | Installed module | Anyone else |
| --- | --- | --- | --- | --- | --- |
| `execute` to allowlisted target | Allowed | Allowed | Allowed | — (use `moduleExecute`) | Blocked |
| `execute` to any other address | Allowed | Allowed | Blocked | — | Blocked |
| `execute` to the account itself (self-call) | Allowed | Allowed | Blocked | Blocked | Blocked |
| `execute` with a valid session key (within expiry, limit, target) | — | — | Allowed | — | Blocked |
| `execute` with an expired, overspent, wrong-target or revoked session key | — | — | Blocked | — | Blocked |
| `executeBatch`, all calls allowed | Allowed | Allowed | Allowed | — | Blocked |
| `executeBatch`, any call privileged | Blocked (whole batch reverts) | Blocked | Blocked | — | Blocked |
| `executeDelegate` | Allowed | Allowed | Blocked | Blocked | Blocked |
| `moduleExecute` to any address except the account | — | — | — | Allowed | Blocked |
| `moduleExecute` to the account itself | — | — | — | Blocked | Blocked |
| `installModule` / `uninstallModule` | Allowed | Allowed | Blocked | Blocked | Blocked |
| `setValidator` / `setExecutor` / `setOwner` | Allowed | Allowed | Blocked | Blocked | Blocked |
| `validateUserOp` | Blocked | Allowed | Blocked | Blocked | Blocked |

Notes on the matrix:
- The EntryPoint column means "inside a UserOperation whose signature
  validated for the owner". The EntryPoint itself never originates an
  action; it only forwards what the owner signed.
- A self-call is how the owner does admin work inside a UserOperation:
  `execute()` calls the account, so inside `setOwner` the caller is
  the account itself. The check that matters is therefore who was
  allowed to start the self-call, not who the inner call appears to
  come from.
- A session key is only as narrow as its policy: the key's allowed
  target, spending limit, expiry and revocation state are checked on
  every executor call, and spend is recorded across calls, so a limit
  cannot be beaten by splitting one large call into many small ones.
  With no session validator set, the coarse allowlist (one target)
  is the executor's only check; with one set, the per-key policy
  replaces it.
- Delegation is not an account permission: an EOA that delegates to
  an implementation runs that implementation's code with the EOA's
  balance and storage. There is no check in the delegation mechanism
  that distinguishes a benign implementation from a hostile one. The
  defences are choosing the implementation, revoking by delegating
  to address(0), and the authorisation nonce, which makes a signed
  authorisation unusable twice.
- A module is trusted once installed, so `moduleExecute` places no
  destination restriction other than "not the account itself". The
  security of modules lives entirely in the install check.

## Trust boundaries

1. **EntryPoint ↔ account.** Only the EntryPoint may call
   `validateUserOp`. Anyone else calling it gets a revert, and the
   EntryPoint only executes after validation returns 0. A signature
   that does not recover to the owner, a wrong nonce, or an expired
   operation all fail validation and nothing executes.
2. **Validator ↔ account.** The validator answers a signature question
   and nothing else. It cannot execute, it cannot change account state,
   and changing which validator is installed is itself privileged.
3. **Executor ↔ account.** The executor's power is the allowlist: one
   target contract, non-privileged calls only. The boundary is enforced
   in `_authorizeExecute` on every path that reaches execution —
   direct, batched, and self-call — because a check present on the
   direct path and absent on another path is the classic bypass.
4. **Module ↔ account.** Installation is the boundary. After that,
   the module is inside the trust perimeter. Uninstalling removes the
   module's execution rights immediately.
5. **Delegatecall.** Delegatecalled code runs with the account's
   storage. The only callers allowed to start a delegatecall are the
   owner and the EntryPoint, because a delegatecall is equivalent to
   running arbitrary code as the account.
6. **Session keys.** The validator answers four questions — is the
   key live, unrevoked, within its spending limit, and calling its
   allowed target — and only the account may ask. The validator
   cannot execute and cannot move funds; granting and revoking keys
   is the owner's job, and changing which validator is installed is
   itself privileged.
7. **Delegation.** The EOA's code is the boundary: once an EOA
   delegates, anyone who can call the EOA can run the
   implementation's code as the EOA. The authorisation signature is
   the gate, the nonce makes it single-use, and delegating to
   address(0) is the revoke.

## Invariants

The invariants that describe the intended permission model, each
covered by tests:

1. Only a validated owner signature (or the owner directly) can cause
   a privileged state change.
2. A nonce is consumed by exactly one successful validation; a
   validated operation cannot execute twice.
3. An executor can never change who owns the account, install or
   remove a module, change the validator, or run code in the
   account's storage context — on any path.
4. A module can never call the account itself, and an uninstalled
   module can execute nothing.
5. A batch either executes entirely within the caller's permissions
   or reverts entirely; a privileged call hidden in a batch does not
   slip through and does not leave earlier calls applied.
6. A session key can only act within its expiry, spending limit,
   allowed target and revocation state, on every path, and spend
   accumulates across calls until the limit is reached.

## Reference defects and what they break

| Variant | Defect | Invariant broken | Demonstrated impact |
| --- | --- | --- | --- |
| A `VulnDirectPrivileged` | `setOwner` has no check | 1 | Any address sets the owner directly |
| B `VulnModuleInstall` | install/uninstall have no check | 1, 4 (install gate) | Attacker installs a hostile module and drains 1 ether |
| C `VulnDelegatecall` | executor may delegatecall | 3 | Executor overwrites the owner (slot 0) |
| D `VulnReplay` | nonce never checked or consumed | 2 | One signed operation executes twice |
| E `VulnSelfCall` | executor may self-call via `execute` | 1, 3 | Executor sets the owner through a self-call; the direct call is still blocked, which is what makes this defect distinct from A |
| F `VulnSessionKey` | session-key policy never enforced | 3, 6 | Executor with an expired, overspent, wrong-target or revoked key executes anyway; with a validator set the executor has no check at all |

## Research questions, answered from the test results

**Can a component with limited execution permissions reach privileged
account functionality?**
Yes, when any execution path omits the check: variant A (direct call),
variant E (self-call through `execute`), and variant C (delegatecall)
each let a limited executor reach `setOwner`. On the correct account
all three paths are blocked, and the tests prove the block on each
path separately — a single-path check would not have caught E.

**Are permission checks consistent across direct, batched and
delegated execution paths?**
On the correct account, yes: the batch test authorises every call
before executing any of them, so a privileged call hidden in a batch
reverts the whole batch with no partial effects. On the vulnerable
variants the inconsistency is the vulnerability itself — E is a
check present on the direct path and absent on the self-call path.

**How do modular account designs prevent privilege escalation
between validators, executors and administrators?**
By separating the questions: the validator only answers "did the
owner sign this?", the executor only answers "is this destination
allowlisted?", and administration (owner, validator, module, executor
changes) only answers "is the caller the owner, the EntryPoint, or
the account itself?". No component's authority is derived from
another component's: the validator cannot execute, the executor
cannot validate, and a module cannot install another module.

**Which invariants best describe the intended permission model?**
The six invariants above. Invariant 3 (an executor can never reach
privileged state on any path) is the sharpest: it is the one the
reference defects violate, and it is the one that requires a test
per path rather than a single test per function.

**Do session-key limits hold across calls, or only per call?**
Across calls: the validator records spend, so two 0.4 ether calls
against a 1 ether limit leave 0.2, and a third 0.4 call is rejected.
On variant F none of it holds — the limit is never consulted.

**What does delegation actually trust?**
The implementation, and nothing else. The tests show a delegated
EOA running benign code (counter increments), the same EOA drained
in one call once it delegates to hostile code, revocation by
delegating to address(0) clearing the code, and a signed
authorisation being unusable a second time. There is no mechanism
in the tests that could have told the two implementations apart
before the delegation was signed.
