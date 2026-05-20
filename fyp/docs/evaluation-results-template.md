# Evaluation Results Template

Use this template after collecting real derivation and OTP data from the HoneyBound dashboard export.

## Data Collection Procedure

1. Start HoneyBound-Web and Connectly.
2. Run repeated enrolment or re-derivation actions that trigger real honeyseed derivation.
3. Run OTP verification attempts covering:
   - successful login
   - invalid OTP
   - honeytrap trigger if demonstrated
4. Open the dashboard and use `Export Evaluation Report`.
5. Copy the reported values into the section below.

Important:

- Use real runs, not simulated chart activity.
- The export already uses stored real derivation timings from `hbw_deriv_log_v1`.
- Report the HTOTP `0.24 ms` figure as a literature baseline, not as a directly equivalent implementation environment.

## Results Section Draft

### Derivation Performance

HoneyBound-Web recorded `[sampleCount]` real derivation samples. The average derivation latency was `[averageMs] ms`, with a minimum of `[minMs] ms`, a maximum of `[maxMs] ms`, and a 95th percentile of `[p95Ms] ms`.

Compared with the cited HTOTP baseline of `0.24 ms`, the prototype differed by `[deltaVsBaselineMs] ms`, equivalent to `[ratioVsBaseline]x` the reported baseline. This comparison should be interpreted cautiously because the cited HTOTP figure comes from prior literature and is not directly equivalent to the browser and WebAuthn-assisted prototype environment used here.

### OTP Outcome Reliability

Across `[totalCheckedEvents]` recorded OTP verification events, the prototype produced `[successCount]` successful logins, `[invalidCount]` invalid OTP outcomes, and `[honeytrapCount]` honeytrap detections. This corresponds to an observed success rate of `[successRatePercent]%` for valid OTP submissions within the test procedure.

### Interpretation

The evaluation shows that HoneyBound-Web successfully captures derivation-time and OTP-outcome metrics in a working prototype setting. The derivation latency remained `[within / above]` the local `300 ms` usability target defined for this prototype. While the measured values are higher than the cited HTOTP baseline, the prototype includes additional browser, JavaScript, PBKDF2, and WebAuthn-related overheads that make direct like-for-like comparison inappropriate.

### Limitations

- The measurements were collected from a prototype implementation rather than a production authenticator stack.
- Results may vary by browser, operating system, CPU, and authenticator hardware.
- Cross-platform evidence should be reported separately if tests were run on Windows, macOS, Android, or iOS.
