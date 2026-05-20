# Implementation Notes

This file records important implementation details and caveats that are easy to miss when reading only the UI or top-level README.

## 1. Browser-Local State

HoneyBound is browser-local by design in the current prototype.

That means:

- accounts in `hbw_accounts_v1` are stored in the current browser profile
- decrypted secret/session caches are stored in browser session state
- the registered WebAuthn credential context is tied to the browser/device environment

Practical consequence:

- opening the same `https://localhost:8443` URL in Chrome and Edge does not automatically show the same HoneyBound state
- a fresh browser can look empty until it is linked/imported as another device

## 2. Real OTP vs Honeyseed Detection Seeds

HoneyBound still generates the visible OTP from the decrypted raw TOTP secret so it remains RFC 6238 compatible.

At the same time:

- Connectly receives a seed bundle containing one real seed plus decoy seeds
- current decoy derivation uses deterministic PRF-derived material
- this allows the exported decoys to be regenerated consistently from the same credential + password combination

This means the implementation is now closer to the dissertation claim than the earlier signature-based version, but it still keeps an encrypted canonical TOTP secret locally for OTP generation.

## 3. Seed-Derivation Versioning

Honeyseed-capable accounts now carry a seed derivation version in the HoneyBound store.

- version `2` = deterministic PRF-based derivation
- older honey accounts can still exist locally from the previous signature-based derivation path

Legacy migration behavior:

- a legacy account remains usable for local OTP generation
- when it is exported/re-linked to Connectly again, HoneyBound migrates it to deterministic PRF derivation and exports the updated seed set

Practical consequence:

- already linked legacy accounts should be re-linked once so Connectly stores the new deterministic decoy set

## 4. Multi-Device Role Of The Phone

The phone is no longer just a lightweight companion view after setup.

Current intended flow:

1. The laptop opens the `Link Device` flow and prepares the phone import bundle.
2. The phone scans the QR and initializes its authenticator.
3. The phone imports the account bundle.
4. After import, the phone opens the full `dashboard.html` and can act as a HoneyBound dashboard client.

This supports the intended recovery story where the phone can continue as the primary HoneyBound client if the laptop is unavailable.

## 5. HTTPS Connectly

Connectly now runs over local HTTPS for this prototype.

Current defaults:

- HoneyBound: `https://localhost:8443`
- Connectly: `https://localhost:3000`

Important implication:

- if Google OAuth is enabled, the redirect URI must also be updated to `https://localhost:3000/auth/google/callback`

## 6. Mobile Dashboard Status

`mobile-dashboard.html` is now mainly an onboarding/recovery surface.

Once the phone already has imported HoneyBound accounts:

- it redirects to the full `dashboard.html`
- the full dashboard becomes the phone's normal home UI

This keeps the UI closer to the laptop dashboard and avoids maintaining two separate long-term dashboard experiences.
