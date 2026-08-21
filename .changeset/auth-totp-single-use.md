---
'@gentleduck/auth': minor
---

Make a TOTP code single-use within its validity window.

`verifyTotp` answered only yes or no, which is not enough to satisfy NIST SP 800-63B's
requirement that a verifier accept a given OTP once per validity period. The drift window
spans three steps, so a code observed once, over the user's shoulder or in a phished
prompt, stayed valid for about ninety seconds. That window is the whole protection on a
privileged step-up.

`matchTotpStep` returns which time step matched, scanning the full window without
short-circuiting for the same reason `verifyTotp` does: stopping early leaks which step
matched. The step is recorded on the enrollment as `lastTotpStep`, and a code matching
that step or an earlier one is refused as a replay.

Confirmation spends its code too, so the code that enrolls a factor cannot immediately be
replayed into a step-up on the enrollment it just created.

One consequence worth knowing: a user who legitimately needs two step-ups inside the same
30-second step must wait for the next code. That is the intended reading of the
requirement.
