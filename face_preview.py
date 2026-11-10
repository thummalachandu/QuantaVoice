"""Optional local camera preview. No biometric decisions, storage or network."""
import tkinter as tk
from tkinter import messagebox

def main():
    root=tk.Tk(); root.withdraw()
    capture=None
    try:
        import cv2
        capture=cv2.VideoCapture(0)
        if not capture.isOpened(): raise RuntimeError('Camera unavailable. Check Windows camera permissions and close other camera apps.')
        title='QuantaVoice camera preview - NOT identity verification - Q to close'
        import time
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            ok,frame=capture.read()
            if not ok: raise RuntimeError('Could not read the camera.')
            cv2.putText(frame,'PREVIEW ONLY - No face match or liveness',(10,30),cv2.FONT_HERSHEY_SIMPLEX,.6,(0,255,255),2)
            cv2.imshow(title,frame)
            if cv2.waitKey(30)&255 in (ord('q'),27): break
            if cv2.getWindowProperty(title,cv2.WND_PROP_VISIBLE)<1: break
    except ImportError:
        messagebox.showerror('Optional camera dependency','Close the preview and restart this file with --camera to install camera support.')
    except Exception as exc: messagebox.showerror('Camera preview',str(exc))
    finally:
        if capture is not None: capture.release()
        try:
            import cv2
            cv2.destroyAllWindows()
        except ImportError: pass
        root.destroy()

if __name__=='__main__': main()
