import subprocess
import time
import sys
import signal


scripts = ["quic_server.py", "vio_server.py"]


def kill_existing_script(script_name):
    """Kill any existing instance of the script."""
    subprocess.run(["pkill", "-f", script_name], stderr=subprocess.DEVNULL)


def run_script(script_name):
    """Start a script, killing any existing instance first."""
    # Use sys.executable to run with the same Python interpreter (venv)
    kill_existing_script(script_name)
    time.sleep(0.5)
    p = subprocess.Popen([sys.executable, script_name])
    return p


processes = []
def signal_handler(sig, frame):
    print("\nShutting down GFK server...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    sys.exit(0)


def register_signals():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def start_server(*, sleep=time.sleep):
    """
    Start GFK server components and store them in `processes`.
    Separated for easier unit testing.
    """
    p1 = run_script(scripts[0])
    sleep(1)
    p2 = run_script(scripts[1])
    processes.extend([p1, p2])  # Modify global list, don't shadow it
    return p1, p2


if __name__ == "__main__":
    register_signals()
    p1, p2 = start_server()
    p1.wait()
    p2.wait()
    print("All subprocesses have completed.")
