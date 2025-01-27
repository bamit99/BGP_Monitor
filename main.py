"""Main entry point for BGP Monitor application."""
import sys
import signal
import tkinter as tk
from gui.main_window import BGPMonitorGUI

def signal_handler(signum, frame):
    """Handle interrupt signals."""
    sys.exit(0)

def main():
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run GUI
    root = tk.Tk()
    app = BGPMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.on_closing()
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()
