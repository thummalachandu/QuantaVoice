import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from cryptography.exceptions import InvalidTag
from seven_flow import Flow, NAMES

BG, CARD, TEXT, CYAN = '#071425', '#10243b', '#e0edfa', '#40d9ff'
DETAILS = {
0: ('SIMULATED VOICE IDENTITY + DEEPFAKE CHECK', 'No speaker-verification or anti-spoof model is connected. Live command transcription is separate and does not establish identity. These buttons are presentation scenarios only.', 'Genuine speaker scenario', 'Deepfake / mismatch scenario'),
3: ('SIMULATED FACE CHECK', 'Demonstrates the decision after face match and liveness. Optional camera preview is available. It does not verify identity or liveness; no Aadhaar lookup or face model is connected.', 'Face + liveness pass scenario', 'Face mismatch / spoof scenario'),
4: ('SIMULATED FIDO2 CHECK', 'Demonstrates device approval. This button does not read fingerprints or produce a WebAuthn assertion.', 'Device approval scenario', 'Device denied scenario'),
5: ('SIMULATED AGENT REVIEW', 'You play the reviewer for this demonstration. No live agent, AI reviewer or call recording service is connected.', 'Reviewer approves scenario', 'Reviewer rejects scenario'),
6: ('SIMULATED VIDEO / BRANCH REVIEW', 'You play the reviewing officer. This is a presentation of the workflow, not completed KYC or a branch visit.', 'Officer approves scenario', 'Officer rejects scenario')}

class Demo:
    def __init__(self, root):
        self.root, self.flow = root, Flow()
        root.title('QuantaVoice — Seven-Layer Demo')
        root.geometry('1080x760'); root.minsize(900,680); root.configure(bg=BG)
        shell=tk.Frame(root,bg=BG); shell.pack(fill='both',expand=True)
        canvas=tk.Canvas(shell,bg=BG,highlightthickness=0)
        self.canvas=canvas
        vertical=ttk.Scrollbar(shell,orient='vertical',command=canvas.yview)
        horizontal=ttk.Scrollbar(shell,orient='horizontal',command=canvas.xview)
        canvas.configure(yscrollcommand=vertical.set,xscrollcommand=horizontal.set)
        shell.rowconfigure(0,weight=1); shell.columnconfigure(0,weight=1)
        canvas.grid(row=0,column=0,sticky='nsew'); vertical.grid(row=0,column=1,sticky='ns')
        horizontal.grid(row=1,column=0,sticky='ew')
        body=tk.Frame(canvas,bg=BG)
        window=canvas.create_window((0,0),window=body,anchor='nw')
        body.bind('<Configure>',lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e: canvas.itemconfigure(window,width=max(1080,e.width)))
        def wheel(e):
            if e.widget.winfo_toplevel()==self.root:
                canvas.yview_scroll(-1 if e.delta>0 or e.num==4 else 1,'units')
        self.root.bind_all('<MouseWheel>',wheel,add='+')
        self.root.bind_all('<Button-4>',wheel,add='+'); self.root.bind_all('<Button-5>',wheel,add='+')
        root=body
        self.heading=self.label(root,'QuantaVoice / Live Seven-Layer Lab',23,CYAN)
        self.heading.pack(anchor='w',padx=24,pady=(18,6))
        self.label(root, 'Real ML-KEM encryption • Simulated identity checks and money • Tummala Chandu', 11).pack(anchor='w',padx=24)
        self.balance = tk.StringVar()
        tk.Label(root,textvariable=self.balance,bg=BG,fg='#70f0be',font=('Arial',17)).pack(anchor='w',padx=24,pady=10)
        top = tk.Frame(root,bg=BG); top.pack(fill='x',padx=24)
        self.label(top,'Recipient').pack(side='left')
        self.rec = tk.Entry(top,font=('Arial',12),width=17); self.rec.pack(side='left',padx=8)
        self.label(top,'Amount INR').pack(side='left')
        self.amt = tk.Entry(top,font=('Arial',12),width=12); self.amt.pack(side='left',padx=8)
        self.button(top,'Start / new demo',self.start).pack(side='left',padx=8)
        self.voice_host=tk.Frame(root,bg=BG); self.voice_host.pack(fill='x',padx=24,pady=(5,0))
        middle=tk.Frame(root,bg=BG,height=440); middle.pack(fill='both',expand=True,padx=24,pady=15)
        left=tk.Frame(middle,bg=CARD,width=330,height=510); left.pack(side='left',fill='y',padx=(0,18)); left.pack_propagate(False)
        self.rows=[]
        for i,name in enumerate(NAMES):
            item=tk.Label(left,text=f'{i+1}. {name}\nWAITING',bg=CARD,fg=TEXT,font=('Arial',11),anchor='w',justify='left',padx=14,pady=5)
            item.pack(fill='x'); self.rows.append(item)
        self.panel=tk.Frame(middle,bg=BG); self.panel.pack(side='left',fill='both',expand=True)
        self.log=scrolledtext.ScrolledText(root,height=4,bg=CARD,fg=TEXT,font=('Consolas',10),state='disabled')
        self.log.pack(fill='x',padx=24,pady=(0,14))
        self.render(); self.write('Ready. Demo PIN: 246810. Start a transaction to walk through all seven layers.')

    def show_security_steps(self):
        self.root.update_idletasks()
        body_height=max(self.canvas.bbox('all')[3],1)
        self.canvas.yview_moveto(max(0,self.panel.winfo_y()+self.panel.master.winfo_y()-15)/body_height)

    def label(self,parent,text,size=12,color=TEXT):
        return tk.Label(parent,text=text,bg=BG,fg=color,font=('Arial',size),justify='left',anchor='w',wraplength=550)
    def button(self,parent,text,fn):
        return tk.Button(parent,text=text,command=fn,bg='#153a56',fg='white',activebackground='#215779',activeforeground='white',relief='flat',padx=12,pady=8,font=('Arial',11))
    def write(self,text):
        self.log.configure(state='normal'); self.log.insert('end',text+'\n'); self.log.see('end'); self.log.configure(state='disabled')
    def start(self):
        try:
            self.flow.start(self.rec.get(),self.amt.get())
            self.write(f'New demonstration: INR {self.flow.amount} to {self.flow.recipient}. Balance preserved; prior approvals cleared.')
        except Exception as exc: messagebox.showerror('Cannot start',str(exc))
        self.render()
    def action(self, fn):
        before=self.flow.stage
        try:
            fn()
            if self.flow.stage > before and before < 7:
                self.write(f'Layer {before+1}: {NAMES[before]} — {self.flow.states[before]}')
        except Exception as exc:
            self.write(str(exc)); messagebox.showerror('Check result',str(exc))
        self.render()
    def render(self):
        f=self.flow
        self.balance.set(f'Simulated balance: INR {f.lab.balance/100:,.2f}')
        for i,row in enumerate(self.rows):
            state='CURRENT STEP' if i==f.stage and not f.blocked else f.states[i]
            color='#ff8d98' if state=='REJECTED' else CYAN if state=='CURRENT STEP' else '#70f0be' if 'PASS' in state else TEXT
            row.configure(text=f'{i+1}. {NAMES[i]}\n{state}',fg=color)
        for widget in self.panel.winfo_children(): widget.destroy()
        if f.stage==-1:
            self.label(self.panel,'Walk through all seven layers',19,CYAN).pack(anchor='w',pady=15)
            self.label(self.panel,'Enter a recipient and amount, then click Start / new demo. PIN and OTP logic execute locally; other identity decisions use explicit demo scenarios.').pack(anchor='w',pady=12)
            return
        self.label(self.panel,f'Locked intent: INR {f.amount} to {f.recipient}',13).pack(anchor='w',pady=8)
        if f.contact_id:
            from contacts import resolve
            self.label(self.panel,resolve(f.contact_id).label,11,CYAN).pack(anchor='w')
            self.label(self.panel,'Note: '+(f.note or '(none)'),11).pack(anchor='w')
        if f.blocked:
            self.label(self.panel,'PAYMENT BLOCKED',20,'#ff8d98').pack(anchor='w',pady=18)
            self.label(self.panel,'No money moved. Later layers cannot override rejection. Click Start / new demo to restart the presentation.').pack(anchor='w')
            return
        if f.stage==8:
            self.label(self.panel,'SIMULATED PAYMENT COMPLETED',18,'#70f0be').pack(anchor='w',pady=15)
            self.label(self.panel,'All seven demonstration steps completed. Real ML-KEM decapsulation and AES-GCM integrity and ML-DSA signature validation succeeded.').pack(anchor='w',pady=10)
            self.button(self.panel,'Run separate quantum simulator',self.quantum).pack(anchor='w',pady=15)
            return
        if f.stage in DETAILS:
            title,desc,yes,no=DETAILS[f.stage]
            self.label(self.panel,title,17,CYAN).pack(anchor='w',pady=12)
            self.label(self.panel,desc).pack(anchor='w',pady=10)
            stage=f.stage
            if stage==3:
                self.button(self.panel,'Open camera preview (not verification)',self.camera).pack(anchor='w',pady=5)
            self.button(self.panel,yes,lambda:self.action(lambda:f.scenario(stage,True))).pack(anchor='w',pady=10)
            self.button(self.panel,no,lambda:self.action(lambda:f.scenario(stage,False))).pack(anchor='w',pady=10)
        elif f.stage==1:
            self.label(self.panel,'LOCAL PIN VERIFICATION',18,CYAN).pack(anchor='w',pady=12)
            self.label(self.panel,'Demo PIN: 246810. Salted scrypt verification is real. Three wrong attempts block this demo session. This public demo PIN is not a banking credential.').pack(anchor='w',pady=10)
            value=tk.Entry(self.panel,show='*',font=('Arial',16)); value.pack(anchor='w',pady=8)
            self.button(self.panel,'Verify PIN',lambda:self.action(lambda:f.verify_pin(value.get()))).pack(anchor='w',pady=10)
        elif f.stage==2:
            self.label(self.panel,'LOCAL OTP • SIMULATED DELIVERY',17,CYAN).pack(anchor='w',pady=12)
            self.label(self.panel,'Generate a six-digit code and enter it below. Expires after 60 seconds; three wrong attempts block this demo. No SMS is sent.').pack(anchor='w',pady=10)
            code=self.label(self.panel,'No code generated',16,'#ffdf95'); code.pack(anchor='w',pady=10)
            def issue():
                code.configure(text='Demo inbox code: '+f.issue_otp())
            self.button(self.panel,'Generate / resend demo OTP',issue).pack(anchor='w',pady=8)
            value=tk.Entry(self.panel,font=('Arial',16)); value.pack(anchor='w',pady=8)
            self.button(self.panel,'Verify OTP',lambda:self.action(lambda:f.verify_otp(value.get()))).pack(anchor='w',pady=8)
        elif f.stage==7:
            self.label(self.panel,'REAL POST-QUANTUM ENCRYPTION',17,CYAN).pack(anchor='w',pady=12)
            self.label(self.panel,'Seven demo gates completed. Encrypt now, optionally test tampering, then confirm within 120 seconds. ML-KEM does not prove identity.').pack(anchor='w',pady=10)
            self.button(self.panel,'Encrypt / renew encrypted intent',self.encrypt).pack(anchor='w',pady=8)
            if f.packet:
                self.button(self.panel,'Test modified ciphertext',self.attack).pack(anchor='w',pady=8)
                self.button(self.panel,'Confirm simulated payment',self.confirm).pack(anchor='w',pady=8)
    def camera(self):
        if not messagebox.askyesno('Camera preview','Open your camera locally? Images are not saved or uploaded. This preview cannot approve payment or establish liveness.'): return
        import subprocess, sys
        from pathlib import Path
        subprocess.Popen([sys.executable,MAIN_FILE,'--camera'])

    def encrypt(self):
        def work():
            elapsed=self.flow.encrypt()
            self.write(f'REAL ML-KEM-768 + AES-GCM + ML-DSA-65: {len(self.flow.packet.kem)} byte KEM ciphertext; {elapsed:.3f} ms encryption. Expires in 120 seconds.')
        self.action(work)
    def attack(self):
        try: self.flow.tamper()
        except InvalidTag: self.write('PASS: modified ciphertext rejected by AES-GCM. Balance unchanged.')
        except Exception as exc: self.write('Test error: '+str(exc))
        else: self.write('FAIL: modified ciphertext accepted unexpectedly.')
    def confirm(self):
        from contacts import resolve
        target=resolve(self.flow.contact_id).label if self.flow.contact_id else self.flow.recipient
        if not messagebox.askyesno('Simulated payment',f'Confirm INR {self.flow.amount} to {target}?\nNote: {self.flow.note or "(none)"}'): return
        def work():
            result=self.flow.confirm()
            self.write('SIMULATED PAYMENT COMPLETED. Real encryption validated. Ref: '+result['id'])
        self.action(work)
    def quantum(self):
        from quantum_experiment import simulate
        self.write('LOCAL SIMULATOR ONLY: '+str({str(k):int(v) for k,v in simulate().items()}))

if __name__=='__main__':
    root=tk.Tk(); Demo(root); root.mainloop()
