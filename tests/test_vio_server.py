import asyncio
import importlib
import sys
import types

import pytest


class _Layer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePacket:
    def __init__(self, *, has_tcp=True, has_ip=True, tcp=None, ip=None):
        self._has_tcp = has_tcp
        self._has_ip = has_ip
        self._tcp = tcp
        self._ip = ip

    def haslayer(self, layer):
        name = getattr(layer, "__name__", str(layer))
        if name == "TCP":
            return self._has_tcp
        if name == "IP":
            return self._has_ip
        return False

    def __getitem__(self, layer):
        name = getattr(layer, "__name__", str(layer))
        if name == "TCP":
            return self._tcp
        if name == "IP":
            return self._ip
        raise KeyError(name)


def _make_packet(*, flags="AP", dport=45000, sport=40000, load=b"x", src="198.51.100.9"):
    tcp = _Layer(flags=flags, dport=dport, sport=sport, load=load)
    ip = _Layer(src=src)
    return FakePacket(tcp=tcp, ip=ip)


async def _wait_until(predicate, *, timeout=1.0, interval=0.01):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if predicate():
            return
        await asyncio.sleep(interval)
    raise AssertionError("condition not met within timeout")


@pytest.fixture()
def vio_server(monkeypatch):
    """
    Import `gfk.server.vio_server` in a hermetic way.

    The module imports `parameters` at import time and also caches raw-socket state,
    so we patch `parameters`, reload the module, and reset its sender cache.
    """
    params = types.SimpleNamespace(
        vps_ip="203.0.113.10",
        vio_tcp_server_port=45000,
        quic_local_ip="127.0.0.1",
        quic_server_port=25000,
        tcp_flags="AP",
        udp_timeout=30,
    )
    monkeypatch.setitem(sys.modules, "parameters", params)

    mod = importlib.import_module("gfk.server.vio_server")
    mod = importlib.reload(mod)

    # Reset sender cache for deterministic tests
    if hasattr(mod, "_basepkt"):
        mod._basepkt = None
    if hasattr(mod, "_skt"):
        mod._skt = None
    return mod


def test_send_to_violated_tcp_is_lazy_and_uses_conf_l3socket(vio_server, monkeypatch):
    calls = {"l3": 0, "sent": []}

    class FakeSock:
        def send(self, pkt):
            calls["sent"].append(pkt)

    def fake_l3socket():
        calls["l3"] += 1
        return FakeSock()

    monkeypatch.setattr(vio_server.conf, "L3socket", fake_l3socket)

    vio_server.send_to_violated_tcp(b"data", "198.51.100.9", 12345)
    vio_server.send_to_violated_tcp(b"data2", "198.51.100.9", 12346)

    # L3socket should be created once (cached)
    assert calls["l3"] == 1
    assert len(calls["sent"]) == 2
    pkt1 = calls["sent"][0]
    assert pkt1[vio_server.IP].dst == "198.51.100.9"
    assert int(pkt1[vio_server.TCP].dport) == 12345


@pytest.mark.parametrize(
    "packet, expected",
    [
        (FakePacket(has_tcp=False, has_ip=True), None),
        (_make_packet(dport=9999), None),
        (_make_packet(flags="A"), None),
        (_make_packet(flags="PA", load=b"hello"), (b"hello", "198.51.100.9", 40000)),
    ],
)
def test_extract_vio_packet(packet, expected, vio_server):
    # (keep a local reference to avoid pytest param confusion)
    assert vio_server.extract_vio_packet(packet, 45000) == expected


@pytest.mark.asyncio
async def test_session_udp_protocol_queue_and_close(vio_server):
    proto = vio_server.SessionUdpProtocol()

    class T:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    t = T()
    proto.connection_made(t)
    proto.datagram_received(b"x", ("127.0.0.1", 1))
    assert await proto.queue.get() == b"x"

    proto.error_received(RuntimeError("boom"))
    assert proto.has_error is True
    assert await proto.queue.get() is None
    assert t.closed is True


@pytest.mark.asyncio
async def test_session_forward_vio_to_quic_sends_until_none(vio_server):
    q = asyncio.Queue()
    sent = []

    class T:
        def sendto(self, data):
            sent.append(data)

    transport = T()
    task = asyncio.create_task(vio_server.session_forward_vio_to_quic(q, transport))
    q.put_nowait(b"one")
    q.put_nowait(b"two")
    q.put_nowait(None)
    await task
    assert sent == [b"one", b"two"]


@pytest.mark.asyncio
async def test_session_forward_quic_to_vio_calls_sender_and_touch(vio_server, monkeypatch):
    proto = vio_server.SessionUdpProtocol()
    touched = {"n": 0}
    sent = []

    def touch():
        touched["n"] += 1

    def fake_send(data, ip, port):
        sent.append((data, ip, port))

    monkeypatch.setattr(vio_server, "send_to_violated_tcp", fake_send)

    task = asyncio.create_task(vio_server.session_forward_quic_to_vio("198.51.100.1", 40000, proto, touch))
    proto.queue.put_nowait(b"r1")
    proto.queue.put_nowait(b"r2")
    proto.queue.put_nowait(None)
    await task

    assert touched["n"] == 2
    assert sent == [(b"r1", "198.51.100.1", 40000), (b"r2", "198.51.100.1", 40000)]


@pytest.mark.asyncio
async def test_start_sniffer_uses_asyncsniffer_and_enqueues(vio_server, monkeypatch):
    q = asyncio.Queue()
    loop = asyncio.get_running_loop()

    class FakeAsyncSniffer:
        instance = None

        def __init__(self, prn=None, filter=None, store=None):
            self.prn = prn
            self.filter = filter
            self.store = store
            self.started = False
            self.stopped = False
            FakeAsyncSniffer.instance = self

        def start(self):
            self.started = True

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(vio_server, "AsyncSniffer", FakeAsyncSniffer)

    sniffer = await vio_server.start_sniffer(q, loop)
    assert sniffer is FakeAsyncSniffer.instance
    assert sniffer.started is True
    assert "dst port" in sniffer.filter

    sniffer.prn(_make_packet(dport=vio_server.vio_tcp_server_port, load=b"x"))

    data, cip, cport = await asyncio.wait_for(q.get(), timeout=1)
    assert (data, cip, cport) == (b"x", "198.51.100.9", 40000)


@pytest.mark.asyncio
async def test_vio_server_core_creates_one_session_per_client(vio_server):
    loop = asyncio.get_running_loop()

    created = []

    class FakeTransport:
        def __init__(self):
            self.sent = []
            self.closed = False

        def sendto(self, data):
            self.sent.append(data)

        def close(self):
            self.closed = True

    async def fake_create_datagram_endpoint(factory, local_addr=None, remote_addr=None):
        created.append((local_addr, remote_addr))
        return FakeTransport(), factory()

    sent_to_client = []

    def fake_send_to_client(data, ip, port):
        sent_to_client.append((data, ip, port))

    core = vio_server.VioServerCore(
        loop=loop,
        quic_local_ip_addr="127.0.0.1",
        quic_server_port_num=25000,
        session_idle_timeout=10,
        create_datagram_endpoint=fake_create_datagram_endpoint,
        send_to_client=fake_send_to_client,
    )

    # First payload for client A creates session
    await core.dispatch_vio_payload(b"a1", "198.51.100.1", 40000)
    assert ("198.51.100.1", 40000) in core.sessions
    assert len(created) == 1
    assert created[0][0] == ("127.0.0.1", 0)
    assert created[0][1] == ("127.0.0.1", 25000)

    # Second payload for client A reuses session (no new datagram endpoint)
    await core.dispatch_vio_payload(b"a2", "198.51.100.1", 40000)
    assert len(created) == 1

    # Client B creates another session
    await core.dispatch_vio_payload(b"b1", "198.51.100.2", 40001)
    assert ("198.51.100.2", 40001) in core.sessions
    assert len(created) == 2

    # Drive VIO->QUIC forwarding for client A (queue consumed by task)
    a_sess = core.sessions[("198.51.100.1", 40000)]
    await _wait_until(lambda: b"a1" in a_sess.transport.sent and b"a2" in a_sess.transport.sent)

    # Drive QUIC->VIO forwarding for client B
    b_sess = core.sessions[("198.51.100.2", 40001)]
    b_sess.protocol.queue.put_nowait(b"reply")
    b_sess.protocol.queue.put_nowait(None)
    await _wait_until(lambda: (b"reply", "198.51.100.2", 40001) in sent_to_client)
    assert (b"reply", "198.51.100.2", 40001) in sent_to_client

    # Cleanup
    a_transport = a_sess.transport
    b_transport = b_sess.transport
    await core.close_session(("198.51.100.1", 40000))
    await core.close_session(("198.51.100.2", 40001))
    assert ("198.51.100.1", 40000) not in core.sessions
    assert ("198.51.100.2", 40001) not in core.sessions
    assert a_transport.closed is True
    assert b_transport.closed is True


@pytest.mark.asyncio
async def test_vio_server_core_cleanup_stale(vio_server):
    loop = asyncio.get_running_loop()

    async def fake_create_datagram_endpoint(factory, local_addr=None, remote_addr=None):
        class FakeTransport:
            def sendto(self, data):
                pass

            def close(self):
                pass

        return FakeTransport(), factory()

    core = vio_server.VioServerCore(
        loop=loop,
        quic_local_ip_addr="127.0.0.1",
        quic_server_port_num=25000,
        session_idle_timeout=1,
        create_datagram_endpoint=fake_create_datagram_endpoint,
    )

    await core.ensure_session("198.51.100.1", 40000)
    assert len(core.sessions) == 1
    key = ("198.51.100.1", 40000)
    # Force staleness
    core.sessions[key].last = core.sessions[key].last - 999
    closed = await core.cleanup_stale(now=loop.time())
    assert closed == 1
    assert len(core.sessions) == 0


@pytest.mark.asyncio
async def test_run_vio_server_starts_and_stops(vio_server, monkeypatch):

    class FakeAsyncSniffer:
        instance = None

        def __init__(self, prn=None, filter=None, store=None):
            self.prn = prn
            self.started = False
            self.stopped = False
            FakeAsyncSniffer.instance = self

        def start(self):
            self.started = True

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(vio_server, "AsyncSniffer", FakeAsyncSniffer)

    # Run briefly; should not hang
    await vio_server.run_vio_server(run_seconds=0.05)
    assert FakeAsyncSniffer.instance is not None
    assert FakeAsyncSniffer.instance.started is True
    assert FakeAsyncSniffer.instance.stopped is True


