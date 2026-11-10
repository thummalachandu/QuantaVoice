import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from live_voice import LiveVoice

class Widget:
    def __init__(self,*args,**kwargs):
        self.options=kwargs; self.selection=(); self.callback=None
    def pack(self,**kwargs): pass
    def configure(self,**kwargs): self.options.update(kwargs)
    def insert(self,*args): pass
    def curselection(self): return self.selection
    def bind(self,event,callback): self.callback=callback

class RecipientSelector(unittest.TestCase):
    def test_explicit_selection_and_correct_account(self):
        listing=Widget(); buttons={}
        def button(parent,text,command):
            widget=Widget(command=command);buttons[text]=widget;return widget
        value=lambda text:SimpleNamespace(get=lambda:text)
        obj=SimpleNamespace(root=Mock(),rec=value('Priya'),amt=value('5000'),
            transcript=value('pay Priya 5000'),note=value(''),label=lambda *a:Widget(),
            button=button,flow=Mock(),render=Mock(),show_security_steps=Mock(),
            status=Mock(),write=Mock())
        contacts=[SimpleNamespace(id='one',name='Priya',label='Priya family'),
                  SimpleNamespace(id='two',name='Priya',label='Priya work')]
        with patch('live_voice.matches',return_value=contacts),patch('live_voice.tk.Toplevel'), \
             patch('live_voice.tk.Listbox',return_value=listing), \
             patch('live_voice.messagebox.askyesno',return_value=True), \
             patch('live_voice.messagebox.showinfo'):
            LiveVoice.choose_recipient(obj,'Priya','5000.00')
            confirm=buttons['Confirm details']
            self.assertEqual(confirm.options['state'],'disabled')
            confirm.options['command']()
            obj.flow.start.assert_not_called()
            listing.selection=(1,);listing.callback()
            self.assertEqual(confirm.options['state'],'normal')
            confirm.options['command']()
            obj.flow.start.assert_called_once_with('Priya','5000.00','two','')
            obj.show_security_steps.assert_called_once()
