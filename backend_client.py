"""Desktop client for the separate backend lab. No operator approval capability."""
import json
import queue
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Redirects are forbidden for a capability-bearing request.')


class Client:
    def __init__(self, launch):
        port = launch['port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid local port.')
        self.url = f'http://127.0.0.1:{port}'
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.fingerprint = launch['fingerprint']
        session = self.call('/session', {}, launch['bootstrap'])
        if session['key_fingerprint'] != self.fingerprint:
            raise ValueError('Local launch fingerprint does not match. Stop the lab.')
        self.token = session['token']

    def call(self, path, data, token=None):
        request = Request(self.url + path, data=json.dumps(data).encode(), method='POST',
                          headers={'Content-Type': 'application/json',
                                   'Authorization': 'Bearer ' + (token or self.token)})
        try:
            with self.opener.open(request, timeout=5) as response:
                result = json.loads(response.read(32768))
        except HTTPError as exc:
            try:
                error = json.loads(exc.read(32768)).get('error', 'Server blocked the request.')
            finally:
                exc.close()
            raise ValueError(error) from exc
        if 'key_fingerprint' in result and result['key_fingerprint'] != self.fingerprint:
            raise ValueError('Server key fingerprint changed. Restart the lab.')
        return result


def main(launch):
    root = tk.Tk()
    root.title('QuantaVoice v15: optional backend lab (SIMULATED)')
    root.geometry('870x720')
    root.minsize(640, 550)
    client = Client(launch)
    pending = None
    fields = {}
    busy = False
    tasks = queue.Queue()
    tk.Label(root, text='Client/server security lab — no real money', font=('Arial', 19, 'bold')).pack(pady=10)
    tk.Label(root, text='Server authorizes each simulated debit. Review occurs in the separate terminal.\n'
             'No actual voice/face/OTP identity verification. QNu is NOT connected.', justify='left').pack(pady=8)
    form = tk.Frame(root); form.pack(fill='x', padx=20)
    for i, (key, label) in enumerate([('recipient', 'Recipient name'), ('destination', 'Demo destination (name@demo)'),
                                    ('rupees', 'Amount in rupees'), ('note', 'Optional note')]):
        tk.Label(form, text=label).grid(row=i, column=0, sticky='w', pady=5)
        variable = tk.StringVar(master=root)
        tk.Entry(form, textvariable=variable, width=50).grid(row=i, column=1, sticky='ew', padx=8)
        fields[key] = variable
    form.columnconfigure(1, weight=1)
    output = scrolledtext.ScrolledText(root, height=20, wrap='word')
    output.pack(fill='both', expand=True, padx=20, pady=10)
    def show(value):
        output.configure(state='normal'); output.insert('end', str(value) + '\n'); output.see('end'); output.configure(state='disabled')
    def invalidate(*_):
        nonlocal pending
        pending = None
        confirm.configure(state='disabled')
    def work(fn, done):
        nonlocal busy
        if busy:
            return
        busy = True
        submit.configure(state='disabled'); confirm.configure(state='disabled'); refresh.configure(state='disabled')
        def task():
            try:
                tasks.put((done, fn(), None))
            except Exception as exc:
                tasks.put((done, None, str(exc)))
        threading.Thread(target=task, daemon=True).start()
    def submitted(result, reviewed_fields):
        nonlocal pending
        if {k: v.get().strip() for k, v in fields.items()} != reviewed_fields:
            show('Details changed while submitting. Submit and review again.')
            return
        result['reviewed_fields'] = reviewed_fields
        pending = result
        show(json.dumps(result, ensure_ascii=False, indent=2))
        show('In the terminal: list, then approve ' + result['intent']['id'] + '\nReview fields and type APPROVE. Then click Confirm here within 120 seconds.')
    def prepare():
        body = {k: v.get().strip() for k, v in fields.items()}
        if not messagebox.askyesno('Review exact details', json.dumps(body, ensure_ascii=False, indent=2) + '\n\nSubmit this simulated payment?', parent=root):
            return
        invalidate()
        work(lambda: client.call('/prepare', body), lambda result: submitted(result, body))
    def confirmed(result):
        invalidate()
        show('SIMULATED payment consumed once. Persistent backend receipt:\n' + json.dumps(result, ensure_ascii=False, indent=2))
    def send_confirm():
        if pending is None:
            return
        if {k: v.get().strip() for k, v in fields.items()} != pending['reviewed_fields']:
            invalidate(); show('Details changed. Submit and review again.'); return
        body = {'id': pending['intent']['id'], 'digest': pending['digest']}
        work(lambda: client.call('/confirm', body), confirmed)
    def poll():
        nonlocal busy
        try:
            while True:
                done, result, error = tasks.get_nowait()
                busy = False
                if error:
                    show('Blocked: ' + error)
                else:
                    done(result)
                submit.configure(state='normal'); refresh.configure(state='normal')
                confirm.configure(state='normal' if pending else 'disabled')
        except queue.Empty:
            pass
        root.after(100, poll)
    buttons = tk.Frame(root); buttons.pack(pady=10)
    submit = tk.Button(buttons, text='Submit for server review', command=prepare); submit.pack(side='left', padx=5)
    confirm = tk.Button(buttons, text='Confirm simulated payment', command=send_confirm, state='disabled'); confirm.pack(side='left', padx=5)
    refresh = tk.Button(buttons, text='Server balance / status', command=lambda: work(lambda: client.call('/status', {}), lambda r: show(json.dumps(r, indent=2))))
    refresh.pack(side='left', padx=5)
    for variable in fields.values():
        variable.trace_add('write', invalidate)
    show('Local server fingerprint: ' + client.fingerprint)
    show('New mode has its own persistent ₹50,000 simulated account. It does not share the original seven-step desktop balance.')
    poll()
    root.mainloop()
