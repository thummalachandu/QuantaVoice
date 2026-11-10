"""Launch the modular QuantaVoice v15 research desktop application."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent / "quantavoice"
sys.path.insert(0, str(MODULE_DIR))

import tkinter as tk  # noqa: E402

from research_ui import ResearchVoice  # noqa: E402


def install_model(language: str) -> None:
    import setup_voice

    choices = {
        "en-in": ("vosk-model-small-en-in-0.4", None),
        "en-us": (
            "vosk-model-small-en-us-0.15",
            "30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498",
        ),
        "hi": ("vosk-model-small-hi-0.22", None),
        "te": ("vosk-model-small-te-0.42", None),
    }
    name, digest = choices[language]
    setup_voice.NAME = name
    setup_voice.URL = f"https://alphacephei.com/vosk/models/{name}.zip"
    if digest is None:
        raise SystemExit(
            "This modular release only has a pinned archive hash for the US-English "
            "model. Download other official Vosk models manually into quantavoice/models/."
        )
    setup_voice.EXPECTED_SHA256 = digest
    setup_voice.setup()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup-model", action="store_true", help="Install pinned US-English Vosk model")
    parser.add_argument("--setup-whisper", action="store_true", help="Download local multilingual Whisper small")
    parser.add_argument("--self-test", action="store_true", help="Run embedded unit tests")
    args = parser.parse_args()
    if args.self_test:
        import runpy

        runpy.run_path(str(Path(__file__).with_name("run_tests.py")), run_name="__main__")
        return
    if args.setup_whisper:
        from whisper_engine import setup
        setup()
        return
    if args.setup_model:
        install_model("en-us")
        return
    root = tk.Tk()
    ResearchVoice(root)
    root.mainloop()


if __name__ == "__main__":
    main()
