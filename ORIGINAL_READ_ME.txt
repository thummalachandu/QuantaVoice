ARCHIVED NOTES FROM AN OLDER VERSION. Follow README.md for v14 startup and speech setup.

QUANTAVOICE LIVE v10 - VOICE PAYMENT DEMO FIX

IMPORTANT: This app only changes a simulated balance. It has no bank/UPI
payment connection. Speaking a command is not biometric authentication.

START
1. Close the old QuantaVoice window. Extract this entire ZIP into a new folder.
2. Double-click START_QUANTAVOICE.cmd. The window title must show Live v10.
   Python 3.12 is required; first dependency setup needs internet.
   Speech-model downloading runs in the background after the window opens.
   Wait for Speech model ready before recording; typed payments work meanwhile.
3. Click Enable simulated payment demo in the security section, or tick
   Presentation scenarios (simulated checks) BEFORE recording.
   Use Show all seven security steps to jump to that section.
   Research mode intentionally blocks unavailable evidence.
4. Select the microphone. Use Test microphone + playback to check it.
5. Click Start live microphone. Wait for LISTENING, then say:
      Pay Chandu five thousand rupees
   Click Stop. Check that the transcript says the correct name and amount.
6. Clear speech opens review. For a warning or incorrect transcript, correct
   the transcript and click Review spoken payment. Do not append k to 5000.
7. If Chandu is new, enter name Chandu, number 1234, payment ID chandu@demo.
   These are fictional demo details. Save now resumes payment review.
8. Select the exact recipient account; click Confirm details and confirm.
   The screen moves to the seven security steps.
9. Complete the presentation steps in order:
   - Genuine speaker scenario (SIMULATED)
   - PIN 246810
   - Generate demo OTP and type the displayed code (no SMS is sent)
   - Face + liveness pass scenario (SIMULATED)
   - Device approval scenario (SIMULATED; optional actual WebAuthn is separate)
   - Reviewer approves scenario (SIMULATED)
   - Officer approves scenario (SIMULATED)
10. Click Encrypt / renew encrypted intent, then Confirm simulated payment.
    A successful demo displays SIMULATED PAYMENT COMPLETED and updates balance.
    Encryption expires after 120 seconds; renew if needed.

IF IT STILL STOPS
- Wrong words: check playback, select your actual microphone, retry in the
  selected model language, or correct the transcript manually.
- Low confidence: automatic review is deliberately paused. Check the text
  and use Review spoken payment. Names are never silently guessed.
- RESEARCH MODE / missing model assets / NOT INTEGRATED: use Presentation
  scenarios for the demonstration, then review the payment again. This does
  not enable real biometric verification or real money transfers.
- Missing speech model: close the app, open PowerShell in its extracted folder:
    .\START_QUANTAVOICE.cmd --setup-model    (Indian English)
    .\START_QUANTAVOICE.cmd --model-us       (US English)
    .\START_QUANTAVOICE.cmd --language hi    (Hindi)
    .\START_QUANTAVOICE.cmd --language te    (Telugu)
  Hindi/Telugu support is limited; accuracy is not guaranteed.
- If the issue remains, capture the full status/error and the recognized text.
  Never share a real PIN, OTP or banking credential.

V10 CHANGES
- Speech model download no longer prevents the app window opening.
- Explicit demo-mode button and a jump-to-security button.
- More vertical space for all seven status rows.
- Spoken decimal amounts: Pay Chandu five thousand point five zero.
- Audio quality measurement includes samples queued when Stop is clicked.
- Windows launcher tries both Python launcher forms and Python on PATH,
  verifies Python 3.12, and preserves setup error codes.

PREVIOUS FIXES RETAINED
- Common name-first phrases now accept optional 'to', 'rupees' or 'rs'.
- New recipient registration resumes review with the same amount.
- Confirmed review scrolls to security steps; startup explains demo mode.
- Model errors now show the matching language command; launcher forwards flags.
- Ambiguous multiple commands, negative amounts, and out-of-range amounts fail.
- Final confirmation and all seven demo gates remain required.

VERIFICATION
56 automated tests pass on Linux Python 3.12.14; details and available dependency
versions are in RELEASE_TEST_RESULTS.json. Includes spoken-text parsing,
review continuation, seven-stage simulated debit, crypto, and replay rejection.
Windows microphone, visual desktop behavior and recognition accuracy could not
be tested here. Run RUN_TESTS.cmd for tests in your installed environment.
There is no claim of 100% testing or live bank payment capability.

EXISTING DATA
A new folder starts with a fresh local directory and dependencies. If needed,
copy QuantaVoice_Data/recipients.json and the models folder from your previous
installation while both apps are closed. Do not copy its Python program over v10.
