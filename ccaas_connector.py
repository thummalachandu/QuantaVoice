"""Telephony ingest: G.711 codecs, RTP parsing and a Twilio Media Streams message adapter.

Pure numpy (the stdlib audioop module is removed in Python 3.13). Turns 8 kHz mu-law/A-law call audio
into the 16 kHz float audio the speaker/anti-spoof models expect. Bandwidth lost on the phone line
is NOT restored. Genesys AudioHook and NICE connectors need vendor accounts and are not implemented.
"""
import base64
import json
import struct

import numpy as np

ULAW_BIAS = 0x84


def ulaw_decode(data):
    u = ~np.frombuffer(bytes(data), dtype=np.uint8)
    sign, exp, mant = u & 0x80, (u >> 4) & 0x07, u & 0x0F
    sample = (((mant.astype(np.int32) << 3) + ULAW_BIAS) << exp) - ULAW_BIAS
    return np.where(sign != 0, -sample, sample).astype(np.int16)


def ulaw_encode(pcm):
    """ITU-T G.711 mu-law (14-bit domain, matching the reference encoder)."""
    x = np.asarray(pcm, dtype=np.int32) >> 2
    neg = x < 0
    mag = np.minimum(np.where(neg, -x, x), 8159) + 33
    exp = np.floor(np.log2(mag)).astype(np.int32) - 5
    mant = (mag >> (np.minimum(exp, 7) + 1)) & 0x0F
    uval = np.where(exp >= 8, 0x7F, (exp << 4) | mant)  # full-scale saturation
    return np.where(neg, uval ^ 0x7F, uval ^ 0xFF).astype(np.uint8).tobytes()


def alaw_decode(data):
    a = np.frombuffer(bytes(data), dtype=np.uint8) ^ 0x55
    sign, exp, mant = a & 0x80, (a >> 4) & 0x07, (a & 0x0F).astype(np.int32)
    sample = np.where(exp == 0, (mant << 4) + 8, ((mant << 4) + 0x108) << np.maximum(exp - 1, 0))
    return np.where(sign != 0, sample, -sample).astype(np.int16)


def alaw_encode(pcm):
    x = np.asarray(pcm, dtype=np.int32)
    sign = np.where(x >= 0, 0x80, 0)
    x = np.minimum(np.abs(np.where(x < 0, -x - 1, x)), 32767)
    exp = np.where(x < 256, 0, np.floor(np.log2(np.maximum(x, 1))).astype(np.int32) - 7)
    exp = np.clip(exp, 0, 7)
    mant = np.where(exp == 0, x >> 4, x >> (exp + 3)) & 0x0F
    return ((sign | (exp << 4) | mant) ^ 0x55).astype(np.uint8).tobytes()


def to_model_audio(pcm16_8k):
    """int16 at 8 kHz -> float32 at 16 kHz in [-1, 1] (linear interpolation)."""
    x = np.asarray(pcm16_8k, dtype=np.float32) / 32768.0
    if len(x) == 0:
        return x
    idx = np.arange(len(x) * 2) / 2.0
    return np.interp(idx, np.arange(len(x)), x).astype(np.float32)


def parse_rtp(packet):
    """RFC 3550 fixed header. Returns dict; payload types 0 = PCMU, 8 = PCMA."""
    if len(packet) < 12:
        raise ValueError('RTP packet too short.')
    b0, b1, seq, ts, ssrc = struct.unpack('!BBHII', packet[:12])
    if b0 >> 6 != 2:
        raise ValueError('Unsupported RTP version.')
    csrc = (b0 & 0x0F) * 4
    offset = 12 + csrc
    if b0 & 0x10:
        if len(packet) < offset + 4:
            raise ValueError('Truncated RTP extension.')
        offset += 4 + 4 * struct.unpack('!H', packet[offset + 2:offset + 4])[0]
    payload = packet[offset:]
    if b0 & 0x20 and payload:
        payload = payload[:-payload[-1]]
    return {'pt': b1 & 0x7F, 'seq': seq, 'ts': ts, 'ssrc': ssrc, 'payload': bytes(payload)}


class RtpReassembler:
    """Reorders within a small window; fills lost packets with silence so timing stays honest."""

    def __init__(self, window=8, frame_samples=160):
        self.window, self.frame, self.buf, self.next = window, frame_samples, {}, None
        self.lost = 0

    def push(self, pkt):
        r = parse_rtp(pkt)
        if r['pt'] not in (0, 8):
            raise ValueError('Only G.711 PCMU/PCMA is supported.')
        dec = ulaw_decode if r['pt'] == 0 else alaw_decode
        if self.next is None:
            self.next = r['seq']
        if ((r['seq'] - self.next) & 0xFFFF) >= 0x8000:
            return np.zeros(0, dtype=np.int16)  # late duplicate
        self.buf[r['seq']] = dec(r['payload'])
        out = []
        while True:
            if self.next in self.buf:
                out.append(self.buf.pop(self.next))
            elif len(self.buf) >= self.window:
                out.append(np.zeros(self.frame, dtype=np.int16)); self.lost += 1
            else:
                break
            self.next = (self.next + 1) & 0xFFFF
        return np.concatenate(out) if out else np.zeros(0, dtype=np.int16)


class TwilioStreamAdapter:
    """Parses Twilio Media Streams JSON (event: connected/start/media/stop), mu-law 8 kHz mono."""
    MAX_SECONDS = 120

    def __init__(self):
        self.pcm, self.started, self.stopped, self.meta = [], False, False, {}

    def feed(self, message):
        m = json.loads(message)
        event = m.get('event')
        if event == 'start':
            fmt = m.get('start', {}).get('mediaFormat', {})
            if fmt.get('encoding') != 'audio/x-mulaw' or fmt.get('sampleRate') != 8000 or fmt.get('channels', 1) != 1:
                raise ValueError('Only 8 kHz mono audio/x-mulaw is supported.')
            self.started, self.meta = True, {'streamSid': m['start'].get('streamSid'),
                                             'callSid': m['start'].get('callSid')}
        elif event == 'media':
            if not self.started or self.stopped:
                raise ValueError('Media outside an active stream.')
            payload = base64.b64decode(m['media']['payload'], validate=True)
            if sum(len(p) for p in self.pcm) + len(payload) > self.MAX_SECONDS * 8000:
                raise ValueError('Call audio exceeds the maximum length.')
            self.pcm.append(ulaw_decode(payload))
        elif event == 'stop':
            self.stopped = True
        elif event not in ('connected', 'mark', 'dtmf'):
            raise ValueError('Unknown stream event.')

    def audio16k(self):
        if not self.pcm:
            raise ValueError('No audio received.')
        return to_model_audio(np.concatenate(self.pcm))
