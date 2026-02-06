import importlib
import types
import sys

import pytest


@pytest.fixture()
def mainserver(monkeypatch):
    mod = importlib.import_module("gfk.server.mainserver")
    mod = importlib.reload(mod)
    mod.processes.clear()
    return mod


def test_kill_existing_script_uses_pkill(mainserver, monkeypatch):
    calls = []

    def fake_run(argv, stderr=None):
        calls.append((argv, stderr))

    monkeypatch.setattr(mainserver.subprocess, "run", fake_run)
    mainserver.kill_existing_script("vio_server.py")
    assert calls
    assert calls[0][0] == ["pkill", "-f", "vio_server.py"]


def test_run_script_kills_then_popen(mainserver, monkeypatch):
    called = {"kill": [], "sleep": [], "popen": []}

    monkeypatch.setattr(mainserver, "kill_existing_script", lambda s: called["kill"].append(s))
    monkeypatch.setattr(mainserver.time, "sleep", lambda s: called["sleep"].append(s))

    class P:
        pass

    def fake_popen(argv):
        called["popen"].append(argv)
        return P()

    monkeypatch.setattr(mainserver.subprocess, "Popen", fake_popen)

    p = mainserver.run_script("quic_server.py")
    assert isinstance(p, P)
    assert called["kill"] == ["quic_server.py"]
    assert called["sleep"] == [0.5]
    assert called["popen"] == [[sys.executable, "quic_server.py"]]


def test_signal_handler_terminates_and_waits_then_exits(mainserver, monkeypatch):
    events = []

    class P:
        def terminate(self):
            events.append("terminate")

        def wait(self, timeout=None):
            events.append(("wait", timeout))

    mainserver.processes[:] = [P(), P()]

    monkeypatch.setattr(mainserver.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as e:
        mainserver.signal_handler(None, None)

    assert e.value.code == 0
    assert events.count("terminate") == 2
    assert ("wait", 3) in events


def test_signal_handler_kills_when_terminate_fails(mainserver, monkeypatch):
    events = []

    class P:
        def terminate(self):
            raise RuntimeError("nope")

        def wait(self, timeout=None):
            raise RuntimeError("nope")

        def kill(self):
            events.append("kill")

    mainserver.processes[:] = [P()]
    monkeypatch.setattr(mainserver.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit):
        mainserver.signal_handler(None, None)

    assert events == ["kill"]


def test_register_signals_sets_sigint_and_sigterm(mainserver, monkeypatch):
    calls = []

    def fake_signal(sig, handler):
        calls.append((sig, handler))

    monkeypatch.setattr(mainserver.signal, "signal", fake_signal)
    mainserver.register_signals()

    assert any(sig == mainserver.signal.SIGINT for sig, _ in calls)
    assert any(sig == mainserver.signal.SIGTERM for sig, _ in calls)


def test_start_server_starts_both_and_stores_processes(mainserver, monkeypatch):
    started = []

    def fake_run_script(name):
        p = types.SimpleNamespace(name=name)
        started.append(name)
        return p

    monkeypatch.setattr(mainserver, "run_script", fake_run_script)

    sleeps = []
    p1, p2 = mainserver.start_server(sleep=lambda s: sleeps.append(s))
    assert started == ["quic_server.py", "vio_server.py"]
    assert sleeps == [1]
    assert mainserver.processes == [p1, p2]

