"""Main entry point for BGP Monitor application."""
import sys
import signal
import tkinter as tk
import logging
import logging.handlers
import json # Import json for formatter
from utils.config_manager import config_manager # Import shared config manager
from gui.main_window import BGPMonitorGUI

def signal_handler(signum, frame):
    """Handle interrupt signals."""
    sys.exit(0)

class JsonSyslogFormatter(logging.Formatter):
    """
    Custom formatter to output log records as JSON,
    including extra fields relevant for SIEM.
    """
    def format(self, record):
        log_entry = {
            'timestamp': self.formatTime(record, self.datefmt),
            'name': record.name,
            'level': record.levelname,
            'message': record.getMessage(),
        }
        # Add standard exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        if record.stack_info:
            log_entry['stack_info'] = self.formatStack(record.stack_info)

        # Add extra fields passed via logger.log(..., extra=...)
        # Filter out standard fields already included
        standard_fields = {'args', 'asctime', 'created', 'exc_info', 'exc_text',
                           'filename', 'funcName', 'levelname', 'levelno', 'lineno',
                           'module', 'msecs', 'message', 'msg', 'name', 'pathname',
                           'process', 'processName', 'relativeCreated', 'stack_info',
                           'thread', 'threadName'}
        if hasattr(record, '__dict__'):
            extra_data = {k: v for k, v in record.__dict__.items() if k not in standard_fields}
            if extra_data:
                log_entry['extra'] = extra_data

        return json.dumps(log_entry)

def setup_logging():
    """Configure logging based on application settings."""
    app_settings = config_manager.load_app_settings()
    log_settings = app_settings.get("logging", {})
    log_level_str = log_settings.get("level", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Basic configuration (console or file - adjust as needed)
    # Ensure handlers are removed before basicConfig to avoid duplicates if run multiple times
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=log_level, format=log_format) # Basic config first

    # Syslog configuration
    syslog_config = log_settings.get("syslog", {})
    if syslog_config.get("enabled", False):
        host = syslog_config.get("host", "localhost")
        port = syslog_config.get("port", 514)
        protocol = syslog_config.get("protocol", "UDP").upper()

        if protocol == "TCP":
            socktype = logging.handlers.socket.SOCK_STREAM
        else: # Default to UDP
            socktype = logging.handlers.socket.SOCK_DGRAM

        try:
            syslog_handler = logging.handlers.SysLogHandler(address=(host, port), socktype=socktype)
            # Use the custom JSON formatter for Syslog
            formatter = JsonSyslogFormatter()
            syslog_handler.setFormatter(formatter)

            # Add handler to root logger
            logging.getLogger().addHandler(syslog_handler)
            logging.info(f"Syslog handler configured for {host}:{port} ({protocol})")
        except Exception as e:
            logging.error(f"Failed to configure Syslog handler for {host}:{port} ({protocol}): {e}")

def main():
    # --- Setup Logging First ---
    setup_logging()
    # --------------------------

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
        # Ensure sys.exit is called even if mainloop raises other exceptions
        # Although KeyboardInterrupt is caught, other Tkinter errors might occur.
        logging.info("Application exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
