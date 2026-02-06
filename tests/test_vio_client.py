import importlib
import sys
import types
import asyncio

import pytest


@pytest.fixture()
def vio_client(monkeypatch):
    """
    Import `gfk.client.vio_client` with a fake `parameters` module.
    """
    params = types.SimpleNamespace(
        vps_ip="198.51.100.10",
        vio_tcp_server_port=443,
        vio_tcp_client_port=23456,
        vio_udp_client_port=30000,
        quic_local_ip="127.0.0.1",
        quic_client_port=20000,
        tcp_flags="AP",
    )
    monkeypatch.setitem(sys.modules, "parameters", params)
    mod = importlib.import_module("gfk.client.vio_client")
    mod = importlib.reload(mod)
    return mod


def _make_queue(*items):
    q = asyncio.Queue()
    for it in items:
        q.put_nowait(it)
    return q


class _Layer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePacket:
    def __init__(self, *, ip_src: str, tcp_sport: int, tcp_flags: str, tcp_load: bytes, has_tcp: bool = True):
        self._has_tcp = has_tcp
        self._ip = _Layer(src=ip_src)
        self._tcp = _Layer(sport=tcp_sport, flags=tcp_flags, load=tcp_load)

    def haslayer(self, layer):
        return self._has_tcp if layer.__name__ == "TCP" else False

    def __getitem__(self, layer):
        if layer.__name__ == "IP":
            return self._ip
        if layer.__name__ == "TCP":
            return self._tcp
        raise KeyError(layer)


class _Slashable:
    """
    Minimal object supporting the scapy-style '/' stacking operator.
    """

    def __init__(self, name: str, kwargs: dict):
        self.name = name
        self.kwargs = kwargs
        self.stack = [(name, kwargs)]

    def __truediv__(self, other):
        out = _Slashable(self.name, self.kwargs)
        out.stack = list(self.stack)
        if isinstance(other, _Slashable):
            out.stack.extend(other.stack)
        else:
            out.stack.append((type(other).__name__, {}))
        return out


def test_ensure_sender_initializes_basepkt_and_socket(vio_client, monkeypatch):
    monkeypatch.setattr(vio_client, "basepkt", None)
    monkeypatch.setattr(vio_client, "skt", None)

    monkeypatch.setattr(vio_client, "IP", lambda **kw: _Slashable("IP", kw))
    monkeypatch.setattr(vio_client, "TCP", lambda **kw: _Slashable("TCP", kw))
    monkeypatch.setattr(vio_client, "Raw", lambda **kw: _Slashable("Raw", kw))

    called = {"l3": 0}

    def fake_l3():
        called["l3"] += 1
        return object()

    monkeypatch.setattr(vio_client.conf, "L3socket", fake_l3)

    vio_client._ensure_sender()
    assert vio_client.basepkt is not None
    assert vio_client.skt is not None
    assert called["l3"] == 1


@pytest.mark.asyncio
async def test_async_sniff_realtime_enqueues_matching_payload(vio_client, monkeypatch):
    q = asyncio.Queue()

    created = {}

    class FakeAsyncSniffer:
        def __init__(self, *, prn, filter, store):
            created["prn"] = prn
            created["filter"] = filter
            created["store"] = store

        def start(self):
            created["started"] = True

    monkeypatch.setattr(vio_client, "AsyncSniffer", FakeAsyncSniffer)

    sniffer = await vio_client.async_sniff_realtime(q)
    assert created["started"] is True
    assert "tcp and src host" in created["filter"]
    assert vio_client.vps_ip in created["filter"]
    assert str(vio_client.vio_tcp_server_port) in created["filter"]

    # matching packet => enqueued
    pkt_ok = FakePacket(
        ip_src=vio_client.vps_ip,
        tcp_sport=vio_client.vio_tcp_server_port,
        tcp_flags="PA",  # order shouldn't matter
        tcp_load=b"HELLO",
    )
    created["prn"](pkt_ok)
    assert await q.get() == b"HELLO"

    # non-matching => not enqueued
    pkt_bad = FakePacket(
        ip_src="203.0.113.99",
        tcp_sport=vio_client.vio_tcp_server_port,
        tcp_flags="AP",
        tcp_load=b"NOPE",
    )
    created["prn"](pkt_bad)
    assert q.empty()


@pytest.mark.asyncio
async def test_async_sniff_realtime_raises_when_sniffer_start_fails(vio_client, monkeypatch):
    q = asyncio.Queue()

    class FakeAsyncSniffer:
        def __init__(self, *, prn, filter, store):
            pass

        def start(self):
            raise RuntimeError("no perms")

    monkeypatch.setattr(vio_client, "AsyncSniffer", FakeAsyncSniffer)

    with pytest.raises(RuntimeError):
        await vio_client.async_sniff_realtime(q)


@pytest.mark.asyncio
@pytest.mark.parametrize("send_raises", [False, True])
async def test_forward_vio_to_quic_sends_or_handles_error(vio_client, send_raises):
    q = _make_queue(b"abc", None)
    sent = []

    class T:
        def sendto(self, data, addr):
            if send_raises:
                raise OSError("boom")
            sent.append((data, addr))

    await vio_client.forward_vio_to_quic(q, T())
    if not send_raises:
        assert sent == [(b"abc", (vio_client.quic_local_ip, vio_client.quic_client_port))]


def test_send_to_violated_TCP_is_lazy_and_sends_packet(vio_client, monkeypatch):
    # Ensure lazy init does not call real L3 socket.
    class FakeSkt:
        def __init__(self):
            self.sent = []

        def send(self, pkt):
            self.sent.append(pkt)

    class FakePkt:
        def __init__(self):
            self.layers = {"TCP": _Layer(load=b"")}

        def copy(self):
            return FakePkt()

        def __getitem__(self, layer):
            # `layer` is the scapy TCP class imported into module
            return self.layers[layer.__name__]

    fake = FakeSkt()
    monkeypatch.setattr(vio_client, "basepkt", FakePkt())
    monkeypatch.setattr(vio_client, "skt", fake)
    # If _ensure_sender tries to replace skt, we'd notice by monkeypatching conf.L3socket.
    monkeypatch.setattr(vio_client.conf, "L3socket", lambda: (_ for _ in ()).throw(AssertionError("should not call")))

    vio_client.send_to_violated_TCP(b"PAYLOAD")
    assert len(fake.sent) == 1
    assert fake.sent[0][vio_client.TCP].load == b"PAYLOAD"


@pytest.mark.asyncio
@pytest.mark.parametrize("send_raises", [False, True])
async def test_forward_quic_to_vio_calls_sender_or_handles_error(vio_client, monkeypatch, send_raises):
    called = []

    def fake_send(data):
        called.append(data)
        if send_raises:
            raise RuntimeError("send failed")

    monkeypatch.setattr(vio_client, "send_to_violated_TCP", fake_send)

    proto = types.SimpleNamespace(queue=_make_queue(b"x", None))
    await vio_client.forward_quic_to_vio(proto)
    assert called == [b"x"]


def test_udp_protocol_datagram_received_enqueues(vio_client):
    p = vio_client.UdpProtocol()
    p.datagram_received(b"hi", ("1.2.3.4", 5))
    assert p.queue.get_nowait() == b"hi"


def test_udp_protocol_connection_made_sets_transport(vio_client):
    p = vio_client.UdpProtocol()

    called = {"extra": 0}

    class T:
        def get_extra_info(self, name):
            assert name == "socket"
            called["extra"] += 1
            return object()

    t = T()
    p.connection_made(t)
    assert p.transport is t
    assert called["extra"] == 1
    p.pause_writing()
    p.resume_writing()


@pytest.mark.parametrize(
    "method_name,arg",
    [
        ("error_received", RuntimeError("boom")),
        ("connection_lost", "bye"),
    ],
)
def test_udp_protocol_sets_flag_and_closes_transport(vio_client, method_name, arg):
    p = vio_client.UdpProtocol()
    closed = {"x": False}

    class T:
        def close(self):
            closed["x"] = True

    p.transport = T()
    getattr(p, method_name)(arg)
    assert p.has_error is True
    assert closed["x"] is True


@pytest.mark.asyncio
async def test_start_udp_server_closes_and_aborts_transport(vio_client, monkeypatch):
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(vio_client.asyncio, "get_event_loop", lambda: loop)

    orig_sleep = asyncio.sleep
    udp_proto_holder = {"p": None}

    async def fast_sleep(_secs):
        await orig_sleep(0)

    monkeypatch.setattr(vio_client.asyncio, "sleep", fast_sleep)

    aborted = asyncio.Event()

    class FakeTransport:
        def close(self):
            return None

        def abort(self):
            aborted.set()

        def get_extra_info(self, _name):  # used by connection_made logger
            return object()

    async def fake_create_datagram_endpoint(factory, local_addr=None):
        p = factory()
        udp_proto_holder["p"] = p
        t = FakeTransport()
        p.connection_made(t)
        # Trigger the cancellation path immediately.
        p.has_error = True
        return t, p

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)

    never = asyncio.Event()

    async def fake_forward(*_args, **_kwargs):
        await never.wait()

    monkeypatch.setattr(vio_client, "forward_quic_to_vio", fake_forward)
    monkeypatch.setattr(vio_client, "forward_vio_to_quic", fake_forward)

    q = asyncio.Queue()
    task = asyncio.create_task(vio_client.start_udp_server(q))
    await asyncio.wait_for(aborted.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_run_vio_client_stops_sniffer(vio_client, monkeypatch):
    stopped = {"x": 0}

    class S:
        def stop(self):
            stopped["x"] += 1

    async def fake_sniff(_q):
        return S()

    async def fake_start_udp_server(_q):
        raise asyncio.CancelledError()

    monkeypatch.setattr(vio_client, "async_sniff_realtime", fake_sniff)
    monkeypatch.setattr(vio_client, "start_udp_server", fake_start_udp_server)

    await vio_client.run_vio_client()
    assert stopped["x"] == 1

