"""Biometric consent notice shown by the desktop app before any voice evidence is captured or sent.

DRAFT TEXT, NOT LEGAL ADVICE. The controller's lawyer must approve the wording, the lawful basis and the retention
period for each market (India DPDP Act 2023, EU/UK GDPR, Australia Privacy Act, Canada PIPEDA). Change NOTICE_VERSION
whenever the text changes: the version is stored with every consent record.
"""
NOTICE_VERSION = 'v17.1-en'

# The purposes the desktop asks for. audit_evidence is not requested by the desktop flow.
DESKTOP_PURPOSES = ('voice_verification', 'anti_spoofing')

NOTICE_TEXT = """QuantaVoice - biometric consent (draft notice, lab build)

What we process
Your voice. To confirm that you are the person asking for a payment, the app measures how closely your voice matches
your enrolled voiceprint and whether the audio looks like a recording or synthetic speech.

Purposes (you consent to both)
1. voice_verification - compare your voice with your voiceprint.
2. anti_spoofing - check the audio for replay or synthetic speech.
Your voice is not used for any other purpose, for advertising or for training models.

What is sent
Only the two numeric scores for this payment, to the authorization service. The recording stays on this device and is
not uploaded by this app.

How long
Your consent lasts 365 days, then expires. A stored voiceprint is deleted at the end of its retention period.

Your choices
You can say no. Without consent no voice evidence is captured or sent and the payment needs a stronger check.
You can withdraw consent at any time on this screen. Withdrawal stops further use at once, including a payment that is
waiting for confirmation.
You can ask for your stored voiceprint to be erased. Backups and copies kept outside the service database are not erased
by this button.

Lab build: simulated funds only. This text is a draft and has not been reviewed by a lawyer."""
