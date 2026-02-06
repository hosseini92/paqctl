import importlib
import sys
import types
import asyncio

import pytest


class FakeStreamDataReceived:
    def __init__(self, stream_id: int, data: bytes, end_stream: bool = False):
        self.stream_id = stream_id
        self.data = data
        self.end_stream = end_stream


class FakeStreamReset:
    def __init__(self, stream_id: int):
        self.stream_id = stream_id


class FakeConnectionTerminated:
    def __init__(self, reason_phrase: str):
        self.reason_phrase = reason_phrase


@pytest.fixture()
def quic_server(monkeypatch):
    """
    Import `gfk.server.quic_server` with a fake `parameters` module.
    """
    params = types.SimpleNamespace(
        udp_timeout=30,
        xray_server_ip_address="127.0.0.1",
        quic_auth_code="AUTH",
    )
    monkeypatch.setitem(sys.modules, "parameters", params)
    mod = importlib.import_module("gfk.server.quic_server")
    mod = importlib.reload(mod)
    return mod


@pytest.fixture()
def quic_server_events(quic_server, monkeypatch):
    """
    Patch event types in `gfk.server.quic_server` for `isinstance` checks.
    """
    monkeypatch.setattr(quic_server, "StreamDataReceived", FakeStreamDataReceived, raising=False)
    monkeypatch.setattr(quic_server, "StreamReset", FakeStreamReset, raising=False)
    monkeypatch.setattr(quic_server, "ConnectionTerminated", FakeConnectionTerminated, raising=False)
    return quic_server


def _new_server_proto(quic_server, *, loop=None):
    """
    Create a TunnelServerProtocol instance without running aioquic base init.
    Tests can override attributes as needed.
    """
    proto = object.__new__(quic_server.TunnelServerProtocol)
    proto._closed_streams = set()
    proto.tcp_connections = {}
    proto.udp_connections = {}
    proto.udp_last_activity = {}
    proto.udp_stream_rx = {}
    proto.loop = loop or types.SimpleNamespace(time=lambda: 0.0)
    return proto


def test_udp_frame_and_reassembler_roundtrip(quic_server):
    framed = quic_server._udp_frame(b"hello") + quic_server._udp_frame(b"world")
    rx = quic_server._UdpReassembler()
    out = rx.feed(framed)
    assert out == [b"hello", b"world"]


def test_udp_reassembler_handles_partial_chunks(quic_server):
    msg = quic_server._udp_frame(b"abc")
    rx = quic_server._UdpReassembler()
    assert rx.feed(msg[:1]) == []
    assert rx.feed(msg[1:2]) == []
    assert rx.feed(msg[2:]) == [b"abc"]


def test_parse_connect_request_allows_coalesced_tail(quic_server):
    tail = quic_server._udp_frame(b"a") + quic_server._udp_frame(b"b")
    parsed = quic_server.parse_connect_request(b"AUTHconnect,udp,51820,!###!"+tail, "AUTH")
    assert parsed is not None
    typ, port, out_tail = parsed
    assert typ == "udp"
    assert port == 51820
    assert out_tail == tail


def test_close_this_stream_is_idempotent(quic_server):
    # Create instance without running aioquic base init
    proto = _new_server_proto(quic_server)

    calls = {"fin": 0, "tx": 0}

    class Q:
        def send_stream_data(self, stream_id, data, end_stream=False):
            calls["fin"] += 1

    proto._quic = Q()
    proto.transmit = lambda: calls.__setitem__("tx", calls["tx"] + 1)

    proto.close_this_stream(10)
    proto.close_this_stream(10)
    assert calls["fin"] == 1
    assert calls["tx"] == 1


@pytest.mark.asyncio
async def test_forward_udp_to_quic_frames_payload(quic_server):
    proto = _new_server_proto(quic_server)
    proto.loop = asyncio.get_running_loop()

    sent = []

    class Q:
        def send_stream_data(self, stream_id, data, end_stream=False):
            sent.append((stream_id, data))

    proto._quic = Q()
    proto.transmit = lambda: None

    class P:
        def __init__(self):
            self.queue = asyncio.Queue()

    p = P()
    # Put one datagram then a sentinel to stop
    p.queue.put_nowait((b"XYZ", ("127.0.0.1", 1)))
    p.queue.put_nowait((None, None))

    await proto.forward_udp_to_quic(5, p)
    assert sent, "expected at least one send_stream_data call"
    assert sent[0][0] == 5
    assert sent[0][1] == quic_server._udp_frame(b"XYZ")


def test_quic_event_received_udp_reassembles_and_updates_activity(quic_server_events):
    quic_server = quic_server_events
    proto = _new_server_proto(quic_server, loop=types.SimpleNamespace(time=lambda: 123.0))

    sent = []

    class T:
        def sendto(self, data):
            sent.append(data)

    transport = T()
    proto.udp_connections = {7: (transport, object())}
    proto.udp_stream_rx[7] = quic_server._UdpReassembler()

    data = quic_server._udp_frame(b"a") + quic_server._udp_frame(b"b")
    proto.quic_event_received(FakeStreamDataReceived(7, data, end_stream=False))

    assert sent == [b"a", b"b"]
    assert proto.udp_last_activity[7] == 123.0


def test_connection_lost_removes_protocol_and_closes_connections(quic_server):
    proto = _new_server_proto(quic_server, loop=types.SimpleNamespace(time=lambda: 0.0))

    class W:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    w1, w2 = W(), W()
    proto.tcp_connections = {1: (object(), w1), 2: (object(), w2)}

    class T:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    t1, t2 = T(), T()
    proto.udp_connections = {3: (t1, object()), 4: (t2, object())}

    # Prevent base class behavior from requiring aioquic internals
    quic_server.QuicConnectionProtocol.connection_lost = lambda self, exc: None  # type: ignore

    quic_server.active_protocols.append(proto)
    proto.connection_lost("x")

    assert proto not in quic_server.active_protocols
    assert w1.closed and w2.closed
    assert t1.closed and t2.closed


@pytest.mark.asyncio
async def test_quic_event_received_new_udp_request_schedules_connect(quic_server_events):
    quic_server = quic_server_events
    proto = _new_server_proto(quic_server)

    called = asyncio.Event()
    args = {}

    async def fake_connect_udp(stream_id, port):
        args["stream_id"] = stream_id
        args["port"] = port
        called.set()

    proto.connect_udp = fake_connect_udp  # type: ignore[assignment]

    proto.quic_event_received(FakeStreamDataReceived(55, b"AUTHconnect,udp,51820,!###!"))
    await asyncio.wait_for(called.wait(), timeout=1)
    assert args["stream_id"] == 55
    assert args["port"] == 51820


@pytest.mark.asyncio
async def test_quic_event_received_buffers_udp_data_until_connect(quic_server_events):
    """
    Ensure we don't drop UDP bytes that arrive before connect_udp finishes.
    """
    quic_server = quic_server_events
    proto = _new_server_proto(quic_server, loop=asyncio.get_running_loop())

    # Make task creation deterministic in this unit test.
    scheduled = []

    def fake_create_task(coro):
        scheduled.append(coro)
        # Prevent "coroutine was never awaited" warnings in this unit test.
        try:
            coro.close()
        except Exception:  # pragma: no cover
            pass
        # Do not actually run it.
        class T:
            def cancel(self):  # pragma: no cover
                return None
        return T()

    proto._create_task = fake_create_task

    # Header + first UDP frame in same event.
    first = quic_server._udp_frame(b"hello")
    proto.quic_event_received(FakeStreamDataReceived(77, b"AUTHconnect,udp,51820,!###!"+first, end_stream=False))
    # Another UDP frame arrives before connect_udp completes.
    second = quic_server._udp_frame(b"world")
    proto.quic_event_received(FakeStreamDataReceived(77, second, end_stream=False))

    type_map, data_map = proto._pending_maps()
    assert type_map[77] == "udp"
    assert bytes(data_map[77]) == first + second
    assert scheduled, "expected connect_udp to be scheduled"


@pytest.mark.asyncio
async def test_connect_udp_flushes_pending_bytes(quic_server):
    proto = _new_server_proto(quic_server, loop=types.SimpleNamespace(time=lambda: 123.0))

    sent = []

    class FakeTransport:
        def sendto(self, data):
            sent.append(data)

        def close(self):  # pragma: no cover
            return None

    async def fake_create_dgram(protocol_factory, remote_addr=None):
        protocol = protocol_factory()
        transport = FakeTransport()
        protocol.connection_made(transport)
        return transport, protocol

    proto._create_datagram_endpoint = fake_create_dgram
    def close_coro_task(coro):
        # don't run forwarder; just close coroutine to avoid warnings
        try:
            coro.close()
        except Exception:  # pragma: no cover
            pass
        return None
    proto._create_task = close_coro_task

    # Seed pending bytes as if they arrived before connect completed.
    type_map, data_map = proto._pending_maps()
    type_map[88] = "udp"
    data_map[88] = bytearray(quic_server._udp_frame(b"a") + quic_server._udp_frame(b"b"))

    await proto.connect_udp(88, 51820)

    assert sent == [b"a", b"b"]
    type_map2, data_map2 = proto._pending_maps()
    assert 88 not in type_map2
    assert 88 not in data_map2


def test_quic_event_received_stream_reset_closes_stream(quic_server_events):
    quic_server = quic_server_events
    proto = _new_server_proto(quic_server)

    closed = []
    proto.close_this_stream = lambda sid: closed.append(sid)  # type: ignore[assignment]
    proto.quic_event_received(FakeStreamReset(9))
    assert closed == [9]


def test_quic_event_received_connection_terminated_calls_connection_lost(quic_server_events):
    proto = _new_server_proto(quic_server_events)
    called = []
    proto.connection_lost = lambda reason: called.append(reason)  # type: ignore[assignment]
    proto.quic_event_received(FakeConnectionTerminated("bye"))
    assert called == ["bye"]

