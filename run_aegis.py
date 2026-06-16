import sys
import os
import traceback
from mitmproxy.tools.main import mitmdump

# A smart stream that writes windowless console errors into a text file
class FileStream:
    def __init__(self, filename):
        self.log = open(filename, "a", encoding="utf-8")
    def write(self, data):
        self.log.write(data)
        self.log.flush()
    def flush(self):
        self.log.flush()
    def isatty(self):
        return False

if __name__ == '__main__':
    # Determine if running as a raw script or a compiled PyInstaller EXE
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    # Redirect hidden terminal streams to our debug file
    if sys.stdout is None or sys.stderr is None:
        debug_stream = FileStream("aegis_debug.log")
        sys.stdout = debug_stream
        sys.stderr = debug_stream

    try:
        # Calculate the absolute path to your proxy script inside the bundle
        script_path = os.path.join(base_path, 'Secure-Proxy.py')
        
        sys.argv = ['mitmdump', '-q', '-s', script_path]
        mitmdump()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)