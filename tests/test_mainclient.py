import importlib
import types
import sys

import pytest


@pytest.fixture()
def mainclient(monkeypatch):
    mod = importlib.import_module("gfk.client.mainclient")
    mod = importlib.reload(mod)
    # Ensure a clean global state per test
    mod.processes.clear()
    return mod


def test_kill_existing_script_uses_pkill(mainclient, monkeypatch):
    calls = []

    def fake_run(argv, stderr=None):
        calls.append((argv, stderr))

    monkeypatch.setattr(mainclient.subprocess, "run", fake_run)
    mainclient.kill_existing_script("vio_client.py")
    assert calls
    assert calls[0][0] == ["pkill", "-f", "vio_client.py"]


def test_run_script_kills_then_popen(mainclient, monkeypatch):
    called = {"kill": [], "sleep": [], "popen": []}

    monkeypatch.setattr(mainclient, "kill_existing_script", lambda s: called["kill"].append(s))
    monkeypatch.setattr(mainclient.time, "sleep", lambda s: called["sleep"].append(s))

    class P:
        pass

    def fake_popen(argv):
        called["popen"].append(argv)
        return P()

    monkeypatch.setattr(mainclient.subprocess, "Popen", fake_popen)

    p = mainclient.run_script("quic_client.py")
    assert isinstance(p, P)
    assert called["kill"] == ["quic_client.py"]
    assert called["sleep"] == [0.5]
    assert called["popen"] == [[sys.executable, "quic_client.py"]]


def test_signal_handler_terminates_and_waits_then_exits(mainclient, monkeypatch):
    events = []

    class P:
        def terminate(self):
            events.append("terminate")

        def wait(self, timeout=None):
            events.append(("wait", timeout))

    mainclient.processes[:] = [P(), P()]

    monkeypatch.setattr(mainclient.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as e:
        mainclient.signal_handler(None, None)

    assert e.value.code == 0
    assert events.count("terminate") == 2
    assert ("wait", 3) in events


def test_signal_handler_kills_when_terminate_fails(mainclient, monkeypatch):
    events = []

    class P:
        def terminate(self):
            raise RuntimeError("nope")

        def wait(self, timeout=None):
            raise RuntimeError("nope")

        def kill(self):
            events.append("kill")

    mainclient.processes[:] = [P()]
    monkeypatch.setattr(mainclient.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit):
        mainclient.signal_handler(None, None)

    assert events == ["kill"]


def test_register_signals_sets_sigint_and_sigterm(mainclient, monkeypatch):
    calls = []

    def fake_signal(sig, handler):
        calls.append((sig, handler))

    monkeypatch.setattr(mainclient.signal, "signal", fake_signal)
    mainclient.register_signals()

    assert any(sig == mainclient.signal.SIGINT for sig, _ in calls)
    assert any(sig == mainclient.signal.SIGTERM for sig, _ in calls)


def test_start_client_starts_both_and_stores_processes(mainclient, monkeypatch):
    started = []

    def fake_run_script(name):
        p = types.SimpleNamespace(name=name)
        started.append(name)
        return p

    monkeypatch.setattr(mainclient, "run_script", fake_run_script)

    sleeps = []
    p1, p2 = mainclient.start_client(sleep=lambda s: sleeps.append(s))
    assert started == ["quic_client.py", "vio_client.py"]
    assert sleeps == [1]
    assert mainclient.processes == [p1, p2]

