"""QuantaVoice v17.3 live security demo launcher. SIMULATED funds and gates, loopback only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'quantavoice'))
from live_demo_server import main

if __name__ == '__main__':
    main()
