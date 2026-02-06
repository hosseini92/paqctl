import importlib
import sys
import types
import asyncio

import pytest


class FakeStreamDataReceived:
    def __init__(self, stream_id: int, data: bytes = b"", end_stream: bool = False):
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
def quic_client(monkeypatch):
    """
    Import `gfk.client.quic_client` with a fake `parameters` module.
    """
    params = types.SimpleNamespace(
        udp_timeout=30,
        quic_auth_code="AUTH",
        quic_verify_cert=False,
        quic_max_data=10**9,
        quic_max_stream_data=10**9,
        quic_idle_timeout=60,
        quic_mtu=1420,
        quic_local_ip="127.0.0.1",
        vio_udp_client_port=30000,
        quic_client_port=20000,
    )
    monkeypatch.setitem(sys.modules, "parameters", params)
    mod = importlib.import_module("gfk.client.quic_client")
    mod = importlib.reload(mod)
    return mod


@pytest.fixture()
def quic_client_events(quic_client, monkeypatch):
    """
    Patch event types in `gfk.client.quic_client` for `isinstance` checks.
    """
    monkeypatch.setattr(quic_client, "StreamDataReceived", FakeStreamDataReceived, raising=False)
    monkeypatch.setattr(quic_client, "StreamReset", FakeStreamReset, raising=False)
    monkeypatch.setattr(quic_client, "ConnectionTerminated", FakeConnectionTerminated, raising=False)
    return quic_client


def _new_client_proto(quic_client, *, loop=None):
    """
    Create a TunnelClientProtocol instance without running aioquic base init.
    Tests can override attributes as needed.
    """
    proto = object.__new__(quic_client.TunnelClientProtocol)
    proto._closing = False
    proto._closed_streams = set()
    proto.loop = loop or types.SimpleNamespace(time=lambda: 0.0)
    proto.tcp_connections = {}
    proto.tcp_syn_wait = {}
    proto.udp_last_activity = {}
    proto.udp_addr_to_stream = {}
    proto.udp_stream_to_addr = {}
    proto.udp_stream_to_transport = {}
    proto.udp_stream_rx = {}
    return proto


def test_udp_frame_and_reassembler_roundtrip(quic_client):
    framed = quic_client._udp_frame(b"hello") + quic_client._udp_frame(b"world")
    rx = quic_client._UdpReassembler()
    out = rx.feed(framed)
    assert out == [b"hello", b"world"]


def test_udp_reassembler_handles_partial_chunks(quic_client):
    msg = quic_client._udp_frame(b"abc")
    rx = quic_client._UdpReassembler()
    assert rx.feed(msg[:1]) == []
    assert rx.feed(msg[1:3]) == []
    assert rx.feed(msg[3:]) == [b"abc"]


def test_close_this_stream_is_idempotent(quic_client):
    proto = _new_client_proto(quic_client)

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
async def test_quic_event_received_udp_reassembles_and_forwards(quic_client_events):
    quic_client = quic_client_events
    proto = _new_client_proto(quic_client)
    proto.udp_stream_to_addr = {9: ("10.0.0.1", 1111)}
    proto.udp_stream_rx = {9: quic_client._UdpReassembler()}

    sent = []

    class T:
        def sendto(self, data, addr):
            sent.append((data, addr))

    proto.udp_stream_to_transport = {9: T()}

    data = quic_client._udp_frame(b"a") + quic_client._udp_frame(b"b")
    proto.quic_event_received(FakeStreamDataReceived(9, data, end_stream=False))
    assert sent == [(b"a", ("10.0.0.1", 1111)), (b"b", ("10.0.0.1", 1111))]


@pytest.mark.asyncio
async def test_quic_event_received_end_stream_closes(quic_client_events):
    proto = _new_client_proto(quic_client_events)

    closed = []
    proto.close_this_stream = lambda sid: closed.append(sid)  # type: ignore[assignment]
    proto.quic_event_received(FakeStreamDataReceived(12, b"", end_stream=True))
    assert closed == [12]


@pytest.mark.asyncio
async def test_quic_event_received_ready_triggers_forward_tcp(quic_client_events):
    quic_client = quic_client_events
    proto = _new_client_proto(quic_client)
    proto.tcp_syn_wait = {5: (object(), object())}

    scheduled = []

    async def fake_forward_tcp_to_quic(stream_id):
        scheduled.append(stream_id)

    proto.forward_tcp_to_quic = fake_forward_tcp_to_quic  # type: ignore[assignment]

    proto.quic_event_received(
        FakeStreamDataReceived(
            5, (quic_client.parameters.quic_auth_code + "i am ready,!###!").encode("utf-8"), end_stream=False
        )
    )
    await asyncio.sleep(0)
    assert scheduled == [5]


def test_quic_event_received_stream_reset_closes(quic_client_events):
    proto = _new_client_proto(quic_client_events)
    closed = []
    proto.close_this_stream = lambda sid: closed.append(sid)  # type: ignore[assignment]
    proto.quic_event_received(FakeStreamReset(7))
    assert closed == [7]


def test_quic_event_received_connection_terminated_calls_connection_lost(quic_client_events):
    proto = _new_client_proto(quic_client_events)
    called = []
    proto.connection_lost = lambda reason: called.append(reason)  # type: ignore[assignment]
    proto.quic_event_received(FakeConnectionTerminated("bye"))
    assert called == ["bye"]


@pytest.mark.asyncio
async def test_forward_udp_to_quic_frames_payload(quic_client):
    proto = _new_client_proto(quic_client, loop=asyncio.get_running_loop())
    proto.udp_addr_to_stream = {("1.2.3.4", 5555): 3}
    proto.udp_stream_to_addr = {3: ("1.2.3.4", 5555)}

    sent = []

    class Q:
        def send_stream_data(self, stream_id, data, end_stream=False):
            sent.append((stream_id, data))

    proto._quic = Q()
    proto.transmit = lambda: None

    class U:
        def __init__(self):
            self.queue = asyncio.Queue()
            self.target_port = 1
            self.transport = None

    udp = U()

    t = asyncio.create_task(proto.forward_udp_to_quic(udp))
    udp.queue.put_nowait((b"XYZ", ("1.2.3.4", 5555)))

    # Wait until one send happens, then cancel the infinite loop
    end = asyncio.get_running_loop().time() + 1.0
    while asyncio.get_running_loop().time() < end and not sent:
        await asyncio.sleep(0)
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t

    assert sent
    assert sent[0][0] == 3
    assert sent[0][1] == quic_client._udp_frame(b"XYZ")


def test_new_udp_stream_initializes_mappings_and_sends_connect(quic_client):
    proto = _new_client_proto(quic_client, loop=types.SimpleNamespace(time=lambda: 1.0))

    class Q:
        def __init__(self):
            self.sent = []
            self._next = 10

        def get_next_available_stream_id(self):
            return self._next

        def send_stream_data(self, stream_id, data, end_stream=False):
            self.sent.append((stream_id, data))

    proto._quic = Q()
    proto.transmit = lambda: None

    class UDP:
        target_port = 51820
        transport = object()

    sid = proto.new_udp_stream(("1.2.3.4", 5555), UDP())
    assert sid == 10
    assert proto.udp_addr_to_stream[("1.2.3.4", 5555)] == 10
    assert proto.udp_stream_to_addr[10] == ("1.2.3.4", 5555)
    assert 10 in proto.udp_stream_rx
    # First send is connect header
    assert proto._quic.sent

