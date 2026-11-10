"""Voice command front end for the existing explicitly simulated seven-stage lab."""
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from seven_layer_demo import Demo, BG, CYAN
from microphone import Microphone, devices, MODEL
from pathlib import Path
from voice_command import parse_payment
from contacts import CONTACTS, matches

class LiveVoice(Demo):
    def __init__(self,root):
        self.mic=Microphone()
        self.closing=False
        self.active=False
        self.voice_source=False
        self.capture_warning=''
        self.final_command=''
        self.capture_error=''
        self.auto_review=tk.BooleanVar(master=root,value=False)
        super().__init__(root)
        self.heading.configure(text='QuantaVoice / One File v3')
        root.title('QuantaVoice — One File v3')
        root.geometry('1120x860'); root.minsize(1000,800)
        self.transcript=tk.StringVar()
        self.signal=tk.StringVar(value='Microphone level: idle')
        self.diagnostic=tk.StringVar(value='Selected microphone: waiting for recording')
        self.status=tk.StringVar(value='Microphone off. Say: Pay Chandu 5000. Review the transcript before payment.')
        box=self.voice_host
        self.mic_choice=ttk.Combobox(box,state='readonly',width=30)
        self.mic_choice.grid(row=0,column=0,padx=(0,6),pady=5)
        self.refresh_btn=self.button(box,'Find microphones',self.refresh_devices)
        self.refresh_btn.grid(row=0,column=1,padx=4)
        self.listen_btn=self.button(box,'Start live microphone',self.listen); self.listen_btn.grid(row=0,column=2,padx=4)
        self.stop_btn=self.button(box,'Stop',self.mic.stop); self.stop_btn.grid(row=0,column=3,padx=4)
        self.stop_btn.configure(state='disabled')
        tk.Label(box,textvariable=self.status,bg=BG,fg=CYAN,font=('Arial',10),wraplength=950,anchor='w').grid(row=1,column=0,columnspan=5,sticky='w',pady=5)
        self.transcript_entry=tk.Entry(box,textvariable=self.transcript,font=('Arial',12),width=62)
        self.transcript_entry.grid(row=2,column=0,columnspan=3,sticky='ew',pady=5)
        tk.Label(box,textvariable=self.signal,bg=BG,fg=CYAN).grid(row=10,column=0,columnspan=5,sticky='w',pady=4)
        tk.Label(box,textvariable=self.diagnostic,bg=BG,fg=CYAN,wraplength=980,anchor='w').grid(row=13,column=0,columnspan=5,sticky='w',pady=4)
        self.review_btn=self.button(box,'Review spoken payment',self.review)
        self.review_btn.grid(row=2,column=3,columnspan=2,padx=4)
        self.note=tk.StringVar()
        tk.Label(box,text='Payment note (optional, 140 characters)',bg=BG,fg=CYAN).grid(row=3,column=0,columnspan=2,sticky='w')
        self.note_entry=tk.Entry(box,textvariable=self.note,width=45)
        self.note_entry.grid(row=3,column=2,columnspan=3,sticky='ew')
        self.button(box,'Use typed payment',self.start).grid(row=4,column=0,sticky='w',pady=4)
        tk.Label(box,text='Unclear speech? Retry, edit the transcript, or type recipient and amount above.',bg=BG,fg=CYAN).grid(row=4,column=1,columnspan=4,sticky='w')
        self.test_btn=self.button(box,'Test microphone + playback',self.test_microphone)
        self.test_btn.grid(row=5,column=0,columnspan=2,sticky='w',pady=4)
        self.button(box,'Play last command recording',self.play_command).grid(row=14,column=0,columnspan=2,sticky='w',pady=4)
        self.button(box,'Save last recording (WAV)',self.save_command).grid(row=14,column=2,columnspan=3,sticky='w',pady=4)
        model_root=Path(__file__).resolve().parent/'models'
        self.model_paths=[model_root/'vosk-model-small-en-in-0.4', MODEL]
        self.model_choice=ttk.Combobox(box,state='readonly',width=34,values=['Indian English','US English (install: --model-us)'])
        self.model_choice.grid(row=5,column=2,columnspan=3,sticky='w')
        self.model_choice.current(0 if (self.model_paths[0]/'am'/'final.mdl').is_file() else 1)
        for entry in (self.rec,self.amt,self.transcript_entry,self.note_entry):
            entry.bind('<KeyRelease>',self.invalidate)
        tk.Checkbutton(box,text='Open payment review after clear speech (no automatic payment)',variable=self.auto_review,bg=BG,fg='white',selectcolor='#153a56').grid(row=11,column=0,columnspan=5,sticky='w',pady=5)
        self.button(box,'Show all seven security steps',self.show_security_steps).grid(row=12,column=0,columnspan=5,sticky='w',pady=5)
        self.refresh_devices()
        root.protocol('WM_DELETE_WINDOW',self.close)
        root.after(100,self.poll)
        self.write('LIVE SPEECH INPUT ADDED. Speech-to-text is not voice biometrics. Review the transcript before continuing into the labeled demo checks.')

    def refresh_devices(self):
        try:
            previous=self.input_devices[self.mic_choice.current()][1] if hasattr(self,'input_devices') and self.mic_choice.current()>=0 else None
            self.input_devices=[(None,'Windows default input')]+devices()
            self.mic_choice['values']=[f'{i}: {name}' if i is not None else name for i,name in self.input_devices]
            self.mic_choice.current(next((i for i,(_,name) in enumerate(self.input_devices) if name==previous),0))
            self.diagnostic.set('Selected microphone: '+self.input_devices[self.mic_choice.current()][1])
        except Exception as exc:
            self.input_devices=[(None,'No microphone available')]
            self.mic_choice['values']=['No microphone available']; self.mic_choice.current(0)
            self.status.set('Microphone unavailable: '+str(exc))

    def test_microphone(self):
        if self.active: return
        from audio_check import open_test
        device=self.input_devices[max(self.mic_choice.current(),0)][0]
        open_test(self.root,device)

    def play_command(self):
        if self.active:
            self.status.set('Click Stop and wait for the recording to finish first.'); return
        if not self.mic.last_audio:
            self.status.set('No completed command recording yet. Start the microphone and record a command.'); return
        try:
            import sounddevice as sd
            import numpy as np
            data,rate,_=self.mic.last_audio
            sd.play(np.frombuffer(data,dtype=np.int16),rate,blocking=False)
            self.status.set('Playing your last command through the default speakers. Check whether your words are audible.')
        except Exception as exc: self.status.set('Playback failed: '+str(exc))

    def save_command(self):
        if self.active:
            self.status.set('Stop recording and wait for transcription before saving.'); return
        if not self.mic.last_audio:
            self.status.set('No completed recording to save yet.'); return
        filename=filedialog.asksaveasfilename(parent=self.root,defaultextension='.wav',
            initialfile='QuantaVoice_command.wav',filetypes=[('WAV audio','*.wav')])
        if not filename: return
        try:
            import wave
            data,rate,_=self.mic.last_audio
            with wave.open(filename,'wb') as target:
                target.setnchannels(1); target.setsampwidth(2); target.setframerate(rate)
                target.writeframes(data)
            self.status.set('Recording saved on your computer. Share it only if you choose to.')
        except Exception as exc: self.status.set('Could not save recording: '+str(exc))

    def listen(self):
        if self.active: return
        if 0<=self.flow.stage<8 and not messagebox.askyesno('New voice command','Recording a new command will clear the current demo approvals. Continue?'): return
        self.capture_warning=''; self.capture_error=''; self.final_command=''
        self.diagnostic.set('Selected microphone: '+self.input_devices[max(self.mic_choice.current(),0)][1]+' | recording…')
        self.flow.reset(); self.render()
        self.transcript.set(''); self.rec.delete(0,'end'); self.amt.delete(0,'end'); self.voice_source=True
        selected=self.mic_choice.current()
        device=self.input_devices[max(selected,0)][0]
        self.active=True
        self.listen_btn.configure(state='disabled'); self.review_btn.configure(state='disabled')
        self.refresh_btn.configure(state='disabled'); self.stop_btn.configure(state='normal')
        self.transcript_entry.configure(state='readonly')
        self.test_btn.configure(state='disabled'); self.model_choice.configure(state='disabled')
        self.mic_choice.configure(state='disabled')
        self.status.set('Starting microphone…')
        try: self.mic.start(device,self.model_paths[self.model_choice.current()])
        except Exception as exc:
            self.active=False; self.controls_idle(); self.status.set(str(exc))

    def controls_idle(self):
        self.listen_btn.configure(state='normal'); self.review_btn.configure(state='normal')
        self.refresh_btn.configure(state='normal'); self.stop_btn.configure(state='disabled')
        self.transcript_entry.configure(state='normal')
        self.test_btn.configure(state='normal'); self.model_choice.configure(state='readonly')
        self.mic_choice.configure(state='readonly')

    def poll(self):
        if self.closing: return
        try:
            while True:
                kind,value=self.mic.events.get_nowait()
                if kind=='status': self.status.set(value)
                elif kind=='partial': self.transcript.set(value)
                elif kind=='quality':
                    self.capture_warning=value
                    self.status.set(value)
                    self.write('Recording quality: '+value)
                elif kind=='diagnostic':
                    self.diagnostic.set(value)
                    self.write('Recording: '+value)
                elif kind=='transcript':
                    self.final_command=value
                    self.transcript.set(value)
                    self.status.set('Recording complete. Check every word, correct if needed, then review.')
                    self.write('Recognized command: '+value)
                elif kind=='level':
                    self.signal.set(f'Live microphone level: {value:.1f}% | '+('Speak closer to the microphone' if value<1 else 'Audio arriving'))
                elif kind=='error':
                    self.capture_error=value
                    self.final_command=''
                    self.transcript.set('')
                    self.status.set('Recording failed: '+value)
                    self.write('Recording failed: '+value)
                    self.write('Seven security steps remain WAITING; no payment started.')
                elif kind=='finished':
                    if not self.active: continue
                    self.active=False; self.controls_idle()
                    self.signal.set('Microphone stopped. Play last command recording to check what was captured.')
                    self.finish_command()
        except queue.Empty: pass
        self.root.after(100,self.poll)

    def finish_command(self):
        command=self.final_command
        self.final_command=''  # duplicate finished events must not reopen review
        if not command:
            self.status.set((self.capture_error or 'No payment command recognized.')+' Seven security steps remain WAITING. '+(self.capture_warning or 'Play the last command recording and retry.'))
            return
        if not self.auto_review.get():
            self.status.set((self.capture_warning+' ' if self.capture_warning else '')+'Recording complete. Check the name and amount in the text, then click Review spoken payment.')
            return
        if self.capture_warning:
            self.status.set(self.capture_warning+' Correct the transcript, then click Review spoken payment.')
            return
        try: parse_payment(command)
        except ValueError as exc:
            self.status.set('Command rejected: '+str(exc)+' Seven steps remain WAITING; no payment started.')
            self.write('Command rejected: '+str(exc))
            return
        self.review()

    def invalidate(self, event=None):
        if self.flow.stage >= 0 and self.flow.stage < 8:
            self.flow.reset(); self.render()
            self.status.set('Payment details edited. Previous approvals cleared; review again.')

    def review(self):
        if self.active: return
        self.flow.reset(); self.render()
        try: recipient,amount=parse_payment(self.transcript.get())
        except ValueError as exc:
            self.status.set('Unclear command. No payment started. Retry, edit text, or use typed payment.')
            return messagebox.showerror('Command needs correction',str(exc))
        self.rec.delete(0,'end'); self.rec.insert(0,recipient)
        self.amt.delete(0,'end'); self.amt.insert(0,amount)
        self.choose_recipient(recipient,amount)

    def start(self):
        if self.active:
            messagebox.showinfo('Recording','Click Stop and wait for the transcript first.')
            return
        self.flow.reset(); self.render()
        from voice_command import amount_value
        try: amount=amount_value(self.amt.get())
        except ValueError as exc: return messagebox.showerror('Check amount',str(exc))
        self.choose_recipient(self.rec.get().strip(),amount)

    def choose_recipient(self, name, amount):
        candidates=matches(name)
        if not candidates:
            return messagebox.showerror('Recipient not found','Type one of: '+', '.join(sorted({c.name for c in CONTACTS}))+'. No fuzzy name matching is used.')
        note=self.note.get().strip()
        snapshot=(self.rec.get(),self.amt.get(),self.transcript.get(),self.note.get())
        if len(note)>140 or any(ord(c)<32 for c in note):
            return messagebox.showerror('Check note','Use one line, at most 140 characters.')
        dialog=tk.Toplevel(self.root); dialog.title('Choose and review recipient'); dialog.configure(bg=BG)
        dialog.transient(self.root); dialog.grab_set()
        self.label(dialog,'Choose the correct person',18,CYAN).pack(padx=20,pady=12)
        self.label(dialog,'Fictional demo contacts. Compare the number and payment ID; a name or face alone cannot identify the destination.').pack(padx=20,pady=8)
        self.label(dialog,'Click a recipient row below. It must turn blue before you continue.').pack(padx=20,pady=4)
        recipient_list=tk.Listbox(dialog,exportselection=False,selectmode=tk.SINGLE,
            height=min(6,max(2,len(candidates))),width=75,font=('Arial',12),
            bg='#153a56',fg='white',selectbackground='#0078d4',selectforeground='white')
        recipient_list.pack(fill='x',padx=20,pady=8)
        for contact in candidates:
            recipient_list.insert('end',contact.label)
        selected_label=self.label(dialog,'No recipient selected',12,CYAN)
        selected_label.pack(padx=20,pady=4)
        self.label(dialog,f'Amount: INR {amount}\nNote: {note or "(none)"}').pack(padx=20,pady=12)
        def accept():
            if snapshot!=(self.rec.get(),self.amt.get(),self.transcript.get(),self.note.get()):
                dialog.destroy(); self.flow.reset(); self.render()
                self.status.set('Payment details changed. Review the new details again.'); return
            selection=recipient_list.curselection()
            contact=candidates[int(selection[0])] if len(selection)==1 else None
            if contact is None:
                messagebox.showinfo('Choose recipient','Select the correct person explicitly.',parent=dialog); return
            if not messagebox.askyesno('Confirm payment details',f'{contact.label}\nINR {amount}\nNote: {note or "(none)"}\n\nContinue to the selected security mode?',parent=dialog): return
            try: self.flow.start(contact.name,amount,contact.id,note)
            except Exception as exc:
                messagebox.showerror('Cannot start',str(exc),parent=dialog); return
            dialog.destroy(); self.render()
            self.show_security_steps()
            self.status.set('Details confirmed. Complete the current security step below; no money has been sent.')
            self.write('Reviewed destination: '+contact.label+'; note: '+(note or '(none)'))
        confirm_button=self.button(dialog,'Confirm details',accept)
        confirm_button.configure(state='disabled')
        confirm_button.pack(pady=8)
        def selection_changed(event=None):
            selection=recipient_list.curselection()
            if len(selection)==1:
                selected_label.configure(text='Selected: '+candidates[int(selection[0])].label)
                confirm_button.configure(state='normal')
            else:
                selected_label.configure(text='No recipient selected')
                confirm_button.configure(state='disabled')
        recipient_list.bind('<<ListboxSelect>>',selection_changed)
        self.button(dialog,'Cancel',dialog.destroy).pack(pady=(0,12))

    def close(self):
        self.closing=True; self.mic.stop(); self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); LiveVoice(root); root.mainloop()
