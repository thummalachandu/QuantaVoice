"""Five-second input test; audio stays in memory, playback is explicit."""
import math
from array import array

def levels(data):
    samples=array('h',data)
    if not samples: return -120.0, 0.0
    rms=math.sqrt(sum(v*v for v in samples)/len(samples))/32768
    return 20*math.log10(max(rms,1e-6)), sum(abs(v)>=32700 for v in samples)/len(samples)

def open_test(parent, device):
    import tkinter as tk
    from tkinter import ttk
    import queue, threading, time
    events=queue.Queue(); stop=threading.Event()
    window=tk.Toplevel(parent); window.title('Microphone test — audio stays in memory')
    window.transient(parent); window.grab_set()
    label=tk.StringVar(value='Record five seconds, then play it back. No payment or transcription runs.')
    tk.Label(window,textvariable=label,wraplength=520,font=('Arial',12)).pack(padx=20,pady=12)
    meter=ttk.Progressbar(window,maximum=60,length=480); meter.pack(padx=20,pady=8)
    recording={'data':b'', 'rate':16000, 'busy':False}
    def capture():
        try:
            import sounddevice as sd
            rate=int(sd.query_devices(device,'input')['default_samplerate'])
            parts=[]; peak=-120.; clipped=0.; count=0
            with sd.RawInputStream(samplerate=rate,device=device,channels=1,dtype='int16') as stream:
                events.put(('status','Speak now for five seconds.'))
                deadline=time.monotonic()+5
                while time.monotonic()<deadline and not stop.is_set():
                    data, overflow=stream.read(max(1,int(rate*.1)))
                    if overflow: raise RuntimeError('Input overflow. Close other audio apps and retry.')
                    raw=bytes(data); parts.append(raw)
                    db,clip=levels(raw); peak=max(peak,db); clipped+=clip; count+=1
                    events.put(('level',db))
            if not stop.is_set(): events.put(('audio',(b''.join(parts),rate,peak,clipped/max(count,1))))
        except Exception as exc: events.put(('error',str(exc)))
        finally: events.put(('done',None))
    def record():
        if recording['busy']: return
        recording['data']=b''; recording['busy']=True
        record_btn.configure(state='disabled'); play_btn.configure(state='disabled')
        label.set('Opening selected microphone…')
        threading.Thread(target=capture,daemon=True).start()
    def play():
        try:
            import sounddevice as sd
            import numpy as np
            sd.play(np.frombuffer(recording['data'],dtype=np.int16),recording['rate'],blocking=False)
            label.set('Playing through your default speakers. Is your voice clear and audible?')
        except Exception as exc: label.set(str(exc))
    record_btn=tk.Button(window,text='Record 5-second test',command=record); record_btn.pack(pady=8)
    play_btn=tk.Button(window,text='Play test recording',command=play,state='disabled'); play_btn.pack(pady=8)
    def close():
        stop.set(); recording['data']=b''
        try:
            import sounddevice as sd
            sd.stop()
        except Exception: pass
        window.destroy()
    tk.Button(window,text='Close and discard audio',command=close).pack(pady=12)
    def poll():
        if stop.is_set(): return
        try:
            while True:
                kind,value=events.get_nowait()
                if kind=='level': meter['value']=max(0,min(60,value+60))
                elif kind in ('status','error'): label.set(value)
                elif kind=='audio':
                    recording['data'],recording['rate'],peak,clip=value
                    advice='Very quiet input: check the microphone/device and input volume.' if peak<-42 else 'Level detected. Play back to check clarity; level alone cannot assess speech quality.'
                    if clip>.01: advice='Clipping detected: reduce microphone input volume.'
                    label.set(f'Peak 100 ms RMS: {peak:.1f} dBFS. '+advice)
                    play_btn.configure(state='normal')
                elif kind=='done': recording['busy']=False; record_btn.configure(state='normal')
        except queue.Empty: pass
        window.after(100,poll)
    window.protocol('WM_DELETE_WINDOW',close); poll()
