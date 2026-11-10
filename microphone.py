"""Explicit, time-bounded, local microphone transcription; no voice identity inference."""
import json
import queue
import threading
import time
import os
from array import array
import math
from pathlib import Path

MODEL = Path(os.environ.get('QUANTAVOICE_VOSK_MODEL', str(Path(__file__).resolve().parent/'models'/'vosk-model-small-en-us-0.15')))

def devices():
    import sounddevice as sd
    return [(i, d['name']) for i,d in enumerate(sd.query_devices()) if d['max_input_channels']>0]

class Microphone:
    def __init__(self):
        self.events=queue.Queue()
        self.stop_event=threading.Event()
        self.thread=None
        self.model=None
        self.last_audio=None
    @property
    def busy(self): return self.thread is not None and self.thread.is_alive()
    def start(self,device=None,model_path=None):
        if self.busy: raise ValueError('A recording is already running.')
        self.last_audio=None
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._record,args=(device,Path(model_path) if model_path else MODEL,),daemon=True)
        self.thread.start()
    def stop(self): self.stop_event.set()
    def _record(self,device,model_path):
        try:
            import sounddevice as sd
            if model_path.name.startswith('whisper-'):
                from whisper_engine import make_recognizer
                self.events.put(('status','Loading Whisper locally. Wait for LISTENING before speaking…'))
                rate=int(sd.query_devices(device,'input')['default_samplerate'])
                rec=make_recognizer(self,model_path.name.removeprefix('whisper-'),rate)
            else:
                from vosk import Model, KaldiRecognizer, SetLogLevel
                if not (model_path/'am'/'final.mdl').is_file():
                    raise RuntimeError('Selected Vosk model is missing. Use Whisper English after running START_QUANTAVOICE.cmd, or follow README for manual Vosk model installation.')
                self.events.put(('status','Loading local Vosk speech model…'))
                if self.model is None or getattr(self,"loaded_path",None)!=model_path:
                    SetLogLevel(-1)
                    self.model=Model(str(model_path))
                    self.loaded_path=model_path
                rate=int(sd.query_devices(device,'input')['default_samplerate'])
                rec=KaldiRecognizer(self.model,rate)
                rec.SetWords(True)
            if self.stop_event.is_set():
                raise RuntimeError('Stopped before microphone opened. Wait for LISTENING before speaking.')
            confidence=[]
            total_samples=0
            energy=0
            clipped=0
            peak_block_rms=0
            def result_text(raw):
                result=json.loads(raw)
                confidence.extend(w['conf'] for w in result.get('result',[]) if 'conf' in w)
                return result.get('text','')
            chunks=queue.Queue(maxsize=100)
            overflow=threading.Event()
            def callback(data, frames, timing, status):
                if status: overflow.set()
                try: chunks.put_nowait(bytes(data))
                except queue.Full: overflow.set()
            texts=[]
            captured=[]
            def consume_audio(data):
                nonlocal peak_block_rms,total_samples,energy,clipped
                captured.append(data)
                samples=array('h',data)
                peak_block_rms=max(peak_block_rms,math.sqrt(sum(v*v for v in samples)/max(len(samples),1))/32768)
                self.events.put(('level',min(100,100*math.sqrt(sum(v*v for v in samples)/max(len(samples),1))/32768)))
                total_samples+=len(samples)
                energy+=sum(v*v for v in samples)
                clipped+=sum(abs(v)>=32700 for v in samples)
            started=time.monotonic()
            with sd.RawInputStream(samplerate=rate,blocksize=int(rate*.1),device=device,dtype='int16',channels=1,callback=callback):
                self.events.put(('status','LISTENING — say one payment, then click Stop. Maximum 12 seconds.'))
                while not self.stop_event.is_set() and time.monotonic()-started<12:
                    if overflow.is_set(): raise RuntimeError('Microphone audio overflow. Close other audio apps and record again.')
                    try: data=chunks.get(timeout=.2)
                    except queue.Empty: continue
                    consume_audio(data)
                    if rec.AcceptWaveform(data):
                        text=result_text(rec.Result())
                        if text: texts.append(text)
                        self.events.put(('partial',' '.join(texts)))
                    else:
                        partial=json.loads(rec.PartialResult()).get('partial','')
                        self.events.put(('partial',' '.join(texts+[partial]).strip()))
            # Consume queued audio captured before the stream was closed.
            while not chunks.empty():
                remaining=chunks.get_nowait(); consume_audio(remaining)
                if rec.AcceptWaveform(remaining):
                    text=result_text(rec.Result())
                    if text: texts.append(text)
            if overflow.is_set(): raise RuntimeError('Audio capture lost samples. Please record again.')
            self.last_audio=(b''.join(captured),rate,time.monotonic())
            rms=math.sqrt(energy/max(total_samples,1))/32768
            duration=total_samples/max(rate,1)
            warnings=[]
            if peak_block_rms<0.008: warnings.append('Microphone level is low: move closer or increase input volume.')
            if clipped/max(total_samples,1)>0.01: warnings.append('Audio is clipping: lower microphone gain.')
            duration=total_samples/max(rate,1)
            self.events.put(('diagnostic',f'Input: {sd.query_devices(device,"input")["name"]} | {duration:.1f} s | average {20*math.log10(max(rms,1e-6)):.1f} dBFS | peak block {20*math.log10(max(peak_block_rms,1e-6)):.1f} dBFS | clipped {100*clipped/max(total_samples,1):.2f}%'))
            if warnings: self.events.put(('quality',' '.join(warnings)+' No payment has been started.'))
            if duration<1.5: raise RuntimeError(f'Recording only {duration:.1f} seconds. Start again, wait for LISTENING, speak, then click Stop. Seven steps remain WAITING.')
            if duration>=1.5:
                self.events.put(('status','Transcribing locally… please wait. The microphone is now off.'))
                tail=result_text(rec.FinalResult())
                transcript=' '.join(texts+[tail]).strip()
            else: transcript=''
            if confidence and min(confidence)<0.65:
                self.events.put(('quality','Some words have low recognizer confidence. Check the transcript before review.'))
            if not transcript: raise RuntimeError('No words recognized. The seven steps are WAITING. Check the selected microphone, recording level, and playback; then retry.')
            self.events.put(('transcript',transcript))
        except Exception as exc:
            self.events.put(('error',str(exc)))
        finally:
            self.events.put(('finished',''))
