from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import sys
from pathlib import Path
import asyncio
import threading
import importlib.util
import io
from contextlib import redirect_stdout, redirect_stderr
import traceback
import logging
import queue
import time

# Add project root to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

# Global variables for test control
active_tests = {}
output_queues = {}

class OutputRedirector:
    def __init__(self, test_id):
        self.test_id = test_id
        self.queue = queue.Queue()
        output_queues[test_id] = self.queue

    def write(self, text):
        if text.strip():  # Only queue non-empty strings
            self.queue.put(text)
            socketio.emit('test_output', {'test_id': self.test_id, 'output': text})

    def flush(self):
        pass

def process_output_queue(test_id):
    while test_id in active_tests and active_tests[test_id]:
        try:
            if test_id in output_queues:
                while not output_queues[test_id].empty():
                    text = output_queues[test_id].get_nowait()
                    socketio.emit('test_output', {'test_id': test_id, 'output': text})
            time.sleep(0.1)
        except Exception as e:
            print(f"Error processing output: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('run_test')
def handle_test(data):
    """Handle test execution request."""
    test_name = data['test']
    test_id = f"{test_name}_{int(time.time())}"
    active_tests[test_id] = True

    # Set up output redirection
    redirector = OutputRedirector(test_id)
    sys.stdout = redirector
    sys.stderr = redirector

    # Start output processing thread
    output_thread = threading.Thread(target=process_output_queue, args=(test_id,))
    output_thread.daemon = True
    output_thread.start()

    try:
        if test_name == 'websocket':
            module = load_module('../test_websocket.py')
            def run_async():
                try:
                    asyncio.run(module.test_websocket())
                except Exception as e:
                    print(f"Error in websocket test: {e}")
                finally:
                    active_tests[test_id] = False
            thread = threading.Thread(target=run_async)
            thread.daemon = True
            thread.start()
            
        elif test_name == 'neo4j':
            module = load_module('../test_neo4j_connection.py')
            def run_test():
                try:
                    module.test_connection()
                finally:
                    active_tests[test_id] = False
            thread = threading.Thread(target=run_test)
            thread.daemon = True
            thread.start()
        
        elif test_name == 'validate':
            module = load_module('../validate_neo4j_data.py')
            def run_test():
                try:
                    module.main()
                finally:
                    active_tests[test_id] = False
            thread = threading.Thread(target=run_test)
            thread.daemon = True
            thread.start()
        
        elif test_name == 'live_updates':
            module = load_module('../verify_live_updates.py')
            def run_async():
                try:
                    asyncio.run(module.main())
                finally:
                    active_tests[test_id] = False
            thread = threading.Thread(target=run_async)
            thread.daemon = True
            thread.start()
        
        elif test_name == 'suspicious':
            module = load_module('../query_suspicious.py')
            def run_test():
                try:
                    module.query_suspicious_updates()
                finally:
                    active_tests[test_id] = False
            thread = threading.Thread(target=run_test)
            thread.daemon = True
            thread.start()

        emit('test_started', {'test_id': test_id, 'test_name': test_name})
    
    except Exception as e:
        error_msg = f"Error running test: {str(e)}\n{traceback.format_exc()}"
        emit('test_output', {'test_id': test_id, 'output': error_msg, 'status': 'error'})
        active_tests[test_id] = False

@socketio.on('stop_test')
def stop_test(data):
    """Stop a running test."""
    test_id = data['test_id']
    if test_id in active_tests:
        active_tests[test_id] = False
        emit('test_stopped', {'test_id': test_id})

def load_module(file_path):
    """Dynamically load a Python module from file path."""
    spec = importlib.util.spec_from_file_location("test_module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5001, debug=True)
