from scapy.all import AsyncSniffer, IP, TCP, Raw, conf
import asyncio
import parameters
import logging
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple, Any, Awaitable

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VioServer")

vps_ip = parameters.vps_ip
vio_tcp_server_port = parameters.vio_tcp_server_port
quic_local_ip = parameters.quic_local_ip
quic_server_port = parameters.quic_server_port
tcp_flags = getattr(parameters, 'tcp_flags', 'AP')

# How long to keep an idle client session (seconds)
SESSION_IDLE_TIMEOUT = int(getattr(parameters, "udp_timeout", 300))

tcp_options = [
    ("MSS", 1280),
    ("WScale", 8),
    ("SAckOK", ""),
]

# Raw-socket sender is initialized lazily (so importing this module doesn't
# require CAP_NET_RAW / root, which also makes unit testing possible).
_basepkt = None
_skt = None


def _ensure_sender():
    global _basepkt, _skt
    if _basepkt is None:
        # Base packet template for server->client violated TCP
        _basepkt = (
            IP(src=vps_ip)
            / TCP(sport=vio_tcp_server_port, seq=1, flags=tcp_flags, ack=0, options=tcp_options)
            / Raw(load=b"")
        )
    if _skt is None:
        _skt = conf.L3socket()


def send_to_violated_tcp(binary_data: bytes, client_ip: str, client_port: int) -> None:
    _ensure_sender()
    new_pkt = _basepkt.copy()
    new_pkt[IP].dst = client_ip
    new_pkt[TCP].dport = client_port
    new_pkt[TCP].load = binary_data
    _skt.send(new_pkt)


def extract_vio_packet(packet, expected_dport: int) -> Optional[Tuple[bytes, str, int]]:
    """
    Extract a violated-TCP payload from a sniffed packet.

    Returns (payload_bytes, client_ip, client_port) or None if packet should be ignored.
    """
    try:
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None
        flags = str(packet[TCP].flags)
        if int(packet[TCP].dport) != int(expected_dport):
            return None
        # Check flags using 'in' to handle different flag orderings (AP vs PA)
        if "A" not in flags or "P" not in flags:
            return None
        payload = bytes(packet[TCP].load)
        client_ip_addr = str(packet[IP].src)
        client_port_num = int(packet[TCP].sport)
        return payload, client_ip_addr, client_port_num
    except Exception:
        return None


class SessionUdpProtocol:
    """
    One UDP "view" into the local QUIC server for a single client.
    QUIC server differentiates clients by (src_ip, src_port), so we must use
    a distinct local UDP source port per client session.
    """

    def __init__(self) -> None:
        self.transport = None
        self.queue: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self.has_error = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        self.queue.put_nowait(data)

    def error_received(self, exc):
        self.has_error = True
        self.queue.put_nowait(None)
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc):
        self.has_error = True
        self.queue.put_nowait(None)
        if self.transport:
            self.transport.close()


async def start_sniffer(incoming_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    logger.info("sniffer started")

    def process_packet(packet):
        extracted = extract_vio_packet(packet, vio_tcp_server_port)
        if extracted is None:
            return
        data1, client_ip, client_port = extracted
        # AsyncSniffer runs in another thread; use thread-safe scheduling.
        loop.call_soon_threadsafe(incoming_queue.put_nowait, (data1, client_ip, client_port))

    sniffer = AsyncSniffer(
        prn=process_packet,
        filter=f"tcp and dst host {vps_ip} and dst port {vio_tcp_server_port}",
        store=False,
    )
    sniffer.start()
    return sniffer


async def session_forward_vio_to_quic(vio_to_quic_q: asyncio.Queue, transport):
    try:
        while True:
            data = await vio_to_quic_q.get()
            if data is None:
                break
            transport.sendto(data)
    except Exception as e:
        logger.info(f"Error forwarding VIO->QUIC: {e}")


async def session_forward_quic_to_vio(client_ip: str, client_port: int, protocol: SessionUdpProtocol, touch):
    try:
        while True:
            data = await protocol.queue.get()
            if data is None:
                break
            touch()
            send_to_violated_tcp(data, client_ip, client_port)
    except Exception as e:
        logger.info(f"Error forwarding QUIC->VIO: {e}")


@dataclass
class VioSession:
    transport: Any
    protocol: SessionUdpProtocol
    vio_to_quic_q: "asyncio.Queue[Optional[bytes]]"
    tasks: Tuple[asyncio.Task, asyncio.Task]
    last: float


class VioServerCore:
    """
    Session manager for multi-client VIO<->QUIC bridging.

    Client identity is (client_ip, client_port) extracted from violated TCP packets.
    """

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        quic_local_ip_addr: str,
        quic_server_port_num: int,
        session_idle_timeout: int,
        create_datagram_endpoint: Callable[..., Awaitable[Tuple[Any, SessionUdpProtocol]]],
        create_task: Callable[[Awaitable], asyncio.Task] = asyncio.create_task,
        send_to_client: Callable[[bytes, str, int], None] = send_to_violated_tcp,
        protocol_factory: Callable[[], SessionUdpProtocol] = SessionUdpProtocol,
    ) -> None:
        self._loop = loop
        self._quic_local_ip = quic_local_ip_addr
        self._quic_server_port = int(quic_server_port_num)
        self._timeout = int(session_idle_timeout)
        self._create_datagram_endpoint = create_datagram_endpoint
        self._create_task = create_task
        self._send_to_client = send_to_client
        self._protocol_factory = protocol_factory

        self.sessions: Dict[Tuple[str, int], VioSession] = {}

    async def close_session(self, key: Tuple[str, int]) -> None:
        sess = self.sessions.pop(key, None)
        if sess is None:
            return
        try:
            sess.vio_to_quic_q.put_nowait(None)
        except Exception:
            pass
        try:
            sess.transport.close()
        except Exception:
            pass
        for t in sess.tasks:
            t.cancel()
        # Drain cancellations to avoid "Task was destroyed but it is pending!"
        await asyncio.gather(*sess.tasks, return_exceptions=True)

    async def ensure_session(self, client_ip_addr: str, client_port_num: int) -> VioSession:
        key = (client_ip_addr, int(client_port_num))
        existing = self.sessions.get(key)
        if existing is not None:
            existing.last = self._loop.time()
            return existing

        transport, protocol = await self._create_datagram_endpoint(
            lambda: self._protocol_factory(),
            local_addr=(self._quic_local_ip, 0),
            remote_addr=(self._quic_local_ip, self._quic_server_port),
        )
        vio_to_quic_q: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()

        def touch() -> None:
            s = self.sessions.get(key)
            if s is not None:
                s.last = self._loop.time()

        async def forward_quic_to_vio_task():
            try:
                while True:
                    data = await protocol.queue.get()
                    if data is None:
                        break
                    touch()
                    try:
                        self._send_to_client(data, client_ip_addr, int(client_port_num))
                    except Exception as e:
                        logger.info(f"send_to_client failed for {client_ip_addr}:{client_port_num}: {e}")
                        break
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.info(f"QUIC->VIO task error for {client_ip_addr}:{client_port_num}: {e}")

        async def forward_vio_to_quic_task():
            try:
                while True:
                    data = await vio_to_quic_q.get()
                    if data is None:
                        break
                    try:
                        transport.sendto(data)
                    except Exception as e:
                        logger.info(f"VIO->QUIC send failed for {client_ip_addr}:{client_port_num}: {e}")
                        break
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.info(f"VIO->QUIC task error for {client_ip_addr}:{client_port_num}: {e}")

        t1 = self._create_task(forward_vio_to_quic_task())
        t2 = self._create_task(forward_quic_to_vio_task())

        sess = VioSession(
            transport=transport,
            protocol=protocol,
            vio_to_quic_q=vio_to_quic_q,
            tasks=(t1, t2),
            last=self._loop.time(),
        )
        self.sessions[key] = sess
        logger.info(f"New client session: {client_ip_addr}:{client_port_num}")
        return sess

    async def dispatch_vio_payload(self, payload: bytes, client_ip_addr: str, client_port_num: int) -> None:
        sess = await self.ensure_session(client_ip_addr, int(client_port_num))
        sess.last = self._loop.time()
        sess.vio_to_quic_q.put_nowait(payload)

    async def cleanup_stale(self, *, now: Optional[float] = None) -> int:
        if now is None:
            now = self._loop.time()
        stale = [k for k, s in self.sessions.items() if now - s.last > self._timeout]
        for k in stale:
            await self.close_session(k)
        return len(stale)


async def run_vio_server(*, run_seconds: Optional[float] = None) -> None:
    loop = asyncio.get_running_loop()
    sniffer = None
    incoming: "asyncio.Queue[Tuple[bytes, str, int]]" = asyncio.Queue()
    stop_event = asyncio.Event()
    tasks: list[asyncio.Task] = []

    core = VioServerCore(
        loop=loop,
        quic_local_ip_addr=quic_local_ip,
        quic_server_port_num=quic_server_port,
        session_idle_timeout=SESSION_IDLE_TIMEOUT,
        create_datagram_endpoint=loop.create_datagram_endpoint,
    )

    async def dispatcher():
        try:
            while True:
                if stop_event.is_set():
                    return
                data, cip, cport = await incoming.get()
                await core.dispatch_vio_payload(data, cip, cport)
        except asyncio.CancelledError:
            return

    async def cleanup():
        try:
            while True:
                if stop_event.is_set():
                    return
                await asyncio.sleep(5)
                closed = await core.cleanup_stale()
                if closed:
                    logger.info(f"Closed {closed} idle session(s)")
        except asyncio.CancelledError:
            return

    try:
        sniffer = await start_sniffer(incoming, loop)
        tasks = [asyncio.create_task(dispatcher()), asyncio.create_task(cleanup())]
        if run_seconds is None:
            await asyncio.gather(*tasks)
        else:
            await asyncio.sleep(run_seconds)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.info(f"vio_server fatal error: {e}")
    finally:
        stop_event.set()
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
        # Close sessions
        for k in list(core.sessions.keys()):
            await core.close_session(k)
        logger.info("vio_server stopped")


if __name__ == "__main__":
    asyncio.run(run_vio_server())
