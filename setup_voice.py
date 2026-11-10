"""One-time download from Vosk's official model host. No microphone access."""
from pathlib import Path, PurePosixPath
import hashlib
import shutil
import tempfile
import urllib.request
import zipfile

NAME='vosk-model-small-en-us-0.15'
URL='https://alphacephei.com/vosk/models/'+NAME+'.zip'
EXPECTED_SHA256='30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498'
ROOT=Path(__file__).resolve().parent/'models'

def setup():
    if (ROOT/NAME/'am'/'final.mdl').is_file():
        print('Speech model already available.'); return
    ROOT.mkdir(exist_ok=True)
    print('Downloading the official Vosk English model (about 40 MB). Internet is needed once.')
    with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
        archive=Path(temporary)/'model.zip'
        request=urllib.request.Request(URL,headers={'User-Agent':'QuantaVoiceLocalPrototype/3'})
        with urllib.request.urlopen(request,timeout=60) as response, archive.open('wb') as target:
            total=0
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>100*1024*1024: raise ValueError('Unexpectedly large model download.')
                target.write(chunk)
                print(f"Downloaded {total / 1048576:.1f} MB", flush=True)
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest!=EXPECTED_SHA256:
            raise ValueError('Speech model archive does not match the pinned release download. Download stopped.')
        print('Model SHA-256 matches the archive tested with this prototype.')
        # This is release pinning against our tested download, not a publisher signature.
        with zipfile.ZipFile(archive) as z:
            if sum(i.file_size for i in z.infolist())>300*1024*1024: raise ValueError('Oversized model contents.')
            for info in z.infolist():
                parts=PurePosixPath(info.filename)
                if parts.is_absolute() or '..' in parts.parts or '\\' in info.filename or ':' in info.filename or parts.parts[0]!=NAME:
                    raise ValueError('Unexpected archive path.')
                if (info.external_attr>>16)&0o170000==0o120000: raise ValueError('Unexpected symbolic link.')
            z.extractall(temporary)
        model=Path(temporary)/NAME
        if not (model/'am'/'final.mdl').is_file(): raise ValueError('Incomplete speech model.')
        if (ROOT/NAME).exists(): raise ValueError('Incomplete model folder exists. Rename it before retrying setup.')
        shutil.move(str(model),str(ROOT/NAME))
    print('Speech model ready.')

if __name__=='__main__': setup()
