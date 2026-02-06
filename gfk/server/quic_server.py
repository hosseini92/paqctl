import asyncio
import logging
import signal
import sys
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
import parameters

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QuicServer")

# Global list to track active protocol instances
active_protocols = []

# Bound how much "early" stream data we buffer while waiting for connect_*().
# This prevents unbounded memory usage if a peer sends lots of bytes before the
# backend socket is established.
_PENDING_MAX_BYTES = 256 * 1024

def parse_connect_request(data: bytes, auth_code: str) -> tuple[str, int, bytes] | None:
    """
    Parse a connect request header from the QUIC stream.

    Expected format (bytes):
      auth + "connect,<tcp|udp>,<port>,!###!"

    Note: QUIC may coalesce bytes, so `data` may also include bytes after the
    delimiter. Those bytes are returned as `tail` and must not be dropped.
    """
    try:
        # Allow coalescing: header may arrive with extra bytes after the delimiter.
        parts = data.split(b",!###!", 1)
        header_part = parts[0]
        tail = parts[1] if len(parts) == 2 else b""

        header = header_part.decode("utf-8", errors="ignore")
        prefix = auth_code + "connect,"
        if not header.startswith(prefix):
            return None
        rest = header[len(prefix):]
        # rest: "udp,51820" or "tcp,443"
        if rest.startswith("tcp,"):
            port = int(rest[4:])
            return ("tcp", port, tail) if port > 0 else None
        if rest.startswith("udp,"):
            port = int(rest[4:])
            return ("udp", port, tail) if port > 0 else None
        return None
    except Exception:
        return None


def _udp_frame(payload: bytes) -> bytes:
    ln = len(payload)
    if ln > 0xFFFF:
        raise ValueError(f"UDP payload too large to frame: {ln}")
    return ln.to_bytes(2, "big") + payload


class _UdpReassembler:
    def __init__(self) -> None:
        self.buf = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        if not chunk:
            return []
        self.buf.extend(chunk)
        out: list[bytes] = []
        while True:
            if len(self.buf) < 2:
                break
            ln = int.from_bytes(self.buf[0:2], "big")
            if len(self.buf) < 2 + ln:
                break
            out.append(bytes(self.buf[2 : 2 + ln]))
            del self.buf[: 2 + ln]
        return out


class TunnelServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        # Optional dependency injection for easier unit testing
        self._create_task = kwargs.pop("create_task", asyncio.create_task)
        self._sleep = kwargs.pop("sleep", asyncio.sleep)
        self._open_connection = kwargs.pop("open_connection", asyncio.open_connection)
        self._create_datagram_endpoint = kwargs.pop("create_datagram_endpoint", None)
        self._now = kwargs.pop("now", None)

        super().__init__(*args, **kwargs)
        self.loop = asyncio.get_event_loop()
        self.tcp_connections = {}  # Map TCP connections to QUIC streams
        self.udp_connections = {}  # Map UDP connections to QUIC streams
        self.udp_last_activity = {}  # Track last activity time for UDP connections
        self.udp_stream_rx = {}  # Per-stream reassembly buffers for UDP frames
        # When a new stream is first seen, we may receive data before the
        # backend TCP/UDP socket is established. Buffer it and replay later.
        self._pending_connect_type = {}  # stream_id -> "tcp" | "udp"
        self._pending_stream_data = {}  # stream_id -> bytearray
        self._closed_streams = set()
        active_protocols.append(self)  # Add this protocol instance to the list
        try:
            self._spawn(self.cleanup_stale_udp_connections())
        except Exception as e:
            logger.info(f"Error in cleanup_stale_udp task: {e}")

    def _spawn(self, coro):
        """
        Create a background task using injected scheduler (for testability).
        Safe to call on objects created via `object.__new__`.
        """
        create_task = getattr(self, "_create_task", asyncio.create_task)
        try:
            return create_task(coro)
        except Exception:
            # Last-resort: don't raise from event handler paths
            return None

    def _pending_maps(self) -> tuple[dict[int, str], dict[int, bytearray]]:
        """
        Ensure and return the pending connect/data maps.

        This is intentionally resilient so unit tests can construct an instance
        via `object.__new__` without running `__init__`.
        """
        type_map = getattr(self, "_pending_connect_type", None)
        if type_map is None:
            type_map = {}
            setattr(self, "_pending_connect_type", type_map)
        data_map = getattr(self, "_pending_stream_data", None)
        if data_map is None:
            data_map = {}
            setattr(self, "_pending_stream_data", data_map)
        return type_map, data_map

    def connection_lost(self, exc):
        logger.info("Quic channel lost")
        if self in active_protocols:
            active_protocols.remove(self)
        super().connection_lost(exc)
        self.close_all_tcp_connections()
        self.close_all_udp_connections()

    def close_all_tcp_connections(self):
        logger.info("Closing all TCP connections from server...")
        for stream_id, (reader, writer) in list(self.tcp_connections.items()):
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
            except Exception:
                pass
        self.tcp_connections.clear()

    def close_all_udp_connections(self):
        logger.info("Closing all UDP connections from server...")
        for stream_id, (transport, _) in list(self.udp_connections.items()):
            logger.info(f"Closing UDP connection for stream {stream_id}...")
            try:
                transport.close()
            except Exception:
                pass
        self.udp_connections.clear()
        self.udp_last_activity.clear()
        self.udp_stream_rx.clear()
        # Clear any pending buffered bytes.
        type_map, data_map = self._pending_maps()
        type_map.clear()
        data_map.clear()


    def close_this_stream(self, stream_id):
        if stream_id in self._closed_streams:
            return
        self._closed_streams.add(stream_id)
        try:
            logger.debug(f"FIN to stream={stream_id} sent")
            self._quic.send_stream_data(stream_id, b"", end_stream=True)  # Send FIN flag
            self.transmit()  # Send the FIN flag over the network
        except Exception as e:

            logger.debug(f"Error closing stream at server: {e}")

        try:
            reader_writer = self.tcp_connections.pop(stream_id, None)
            if reader_writer is not None:
                try:
                    reader_writer[1].close()
                except Exception:
                    pass

            transport_proto = self.udp_connections.pop(stream_id, None)
            if transport_proto is not None:
                try:
                    transport_proto[0].close()
                except Exception:
                    pass
                self.udp_last_activity.pop(stream_id, None)
                self.udp_stream_rx.pop(stream_id, None)
            # Clear any pending buffered bytes.
            type_map, data_map = self._pending_maps()
            type_map.pop(stream_id, None)
            data_map.pop(stream_id, None)
        except Exception as e:
            logger.info(f"Error closing socket at server: {e}")




    async def cleanup_stale_udp_connections(self):
        logger.info("UDP cleanup task running!")
        check_time = min(parameters.udp_timeout,60)
        while True:
            await getattr(self, "_sleep", asyncio.sleep)(check_time)  # Run cleanup periodically
            now_fn = getattr(self, "_now", None)
            loop = getattr(self, "loop", asyncio.get_event_loop())
            current_time = (now_fn() if callable(now_fn) else loop.time())
            stale_streams = [
                stream_id for stream_id, last_time in self.udp_last_activity.items()
                if current_time - last_time > parameters.udp_timeout
            ]
            for stream_id in stale_streams:
                logger.info(f"idle UDP stream={stream_id} timeout reached")
                self.close_this_stream(stream_id)



    async def forward_tcp_to_quic(self, stream_id, reader):
        logger.info(f"Task TCP to QUIC started")
        try:
            while True:
                data = await reader.read(4096)  # Read data from TCP socket
                if not data:
                    break
                # logger.info(f"Forwarding data from TCP to QUIC on stream {stream_id}")
                self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                self.transmit()  # Flush
        except Exception as e:
            logger.info(f"Error forwarding TCP to QUIC: {e}")
        finally:
            logger.info(f"Task TCP to QUIC Ended")
            self.close_this_stream(stream_id)



    async def connect_tcp(self, stream_id, target_port):
        logger.info(f"Connecting to TCP:{target_port}...")
        try:
            open_conn = getattr(self, "_open_connection", asyncio.open_connection)
            reader, writer = await open_conn(parameters.xray_server_ip_address, target_port)
            logger.info(f"TCP connection established for stream {stream_id} to port {target_port}")

            # Start forwarding data from TCP to QUIC
            self._spawn(self.forward_tcp_to_quic(stream_id, reader))

            resp_data = parameters.quic_auth_code + "i am ready,!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=resp_data.encode("utf-8"), end_stream=False)
            self.transmit()  # Flush

            self.tcp_connections[stream_id] = (reader, writer)

            # Flush any buffered stream bytes that arrived before connect completed.
            type_map, data_map = self._pending_maps()
            pending = data_map.pop(stream_id, None)
            type_map.pop(stream_id, None)
            if pending:
                try:
                    writer.write(bytes(pending))
                    await writer.drain()
                except Exception as e:
                    logger.info(f"Failed to flush pending TCP bytes for stream {stream_id}: {e}")
        except Exception as e:
            logger.info(f"Failed to establish TCP:{target_port} connection: {e}")
            type_map, data_map = self._pending_maps()
            type_map.pop(stream_id, None)
            data_map.pop(stream_id, None)
            self.close_this_stream(stream_id)



    async def forward_udp_to_quic(self, stream_id, protocol):
        logger.info(f"Task UDP to QUIC started")
        try:
            while True:
                data, _ = await protocol.queue.get()  # Wait for data from UDP
                if data is None:
                    break
                # logger.info(f"Forwarding data from UDP to QUIC on stream {stream_id}")
                self._quic.send_stream_data(stream_id=stream_id, data=_udp_frame(data), end_stream=False)
                self.transmit()  # Flush
                now_fn = getattr(self, "_now", None)
                loop = getattr(self, "loop", asyncio.get_event_loop())
                self.udp_last_activity[stream_id] = (now_fn() if callable(now_fn) else loop.time())
        except Exception as e:
            logger.info(f"Error forwarding UDP to QUIC: {e}")
        finally:
            logger.info(f"Task UDP to QUIC Ended")
            self.close_this_stream(stream_id)


    async def connect_udp(self, stream_id, target_port):
        class UdpProtocol:
            def __init__(self):
                self.transport = None
                self.queue = asyncio.Queue()
                self.stream_id = stream_id

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                logger.debug("UDP datagram received from %s (%d bytes)", addr, len(data) if data else 0)
                self.queue.put_nowait((data, addr))

            def error_received(self, exc):
                logger.info(f"UDP error received: {exc}")
                self.queue.put_nowait((None, None)) # to cancel task
                if self.transport:
                    self.transport.close()
                    logger.info("UDP transport closed")

            def connection_lost(self, exc):
                logger.info("UDP connection lost.")
                self.queue.put_nowait((None, None)) # to cancel task
                if self.transport:
                    self.transport.close()
                    logger.info("UDP transport closed")

        try:
            # Create a UDP socket
            logger.info(f"Connecting to UDP:{target_port}...")
            loop = asyncio.get_event_loop()
            create_dgram = getattr(self, "_create_datagram_endpoint", None) or loop.create_datagram_endpoint
            transport, protocol = await create_dgram(
                UdpProtocol,
                remote_addr=(parameters.xray_server_ip_address, target_port)
            )
            self.udp_connections[stream_id] = (transport, protocol)
            now_fn = getattr(self, "_now", None)
            loop2 = getattr(self, "loop", loop)
            self.udp_last_activity[stream_id] = (now_fn() if callable(now_fn) else loop2.time())
            self.udp_stream_rx[stream_id] = _UdpReassembler()
            logger.info(f"UDP connection established for stream {stream_id} to port {target_port}")

            self._spawn(self.forward_udp_to_quic(stream_id, protocol))

            # Flush any buffered stream bytes that arrived before connect completed.
            type_map, data_map = self._pending_maps()
            pending = data_map.pop(stream_id, None)
            type_map.pop(stream_id, None)
            if pending:
                rx = self.udp_stream_rx.get(stream_id)
                if rx is None:
                    rx = _UdpReassembler()
                    self.udp_stream_rx[stream_id] = rx
                for datagram in rx.feed(bytes(pending)):
                    transport.sendto(datagram)
                now_fn = getattr(self, "_now", None)
                loop3 = getattr(self, "loop", loop)
                self.udp_last_activity[stream_id] = (now_fn() if callable(now_fn) else loop3.time())
        except Exception as e:
            logger.info(f"Failed to establish UDP connection: {e}")
            type_map, data_map = self._pending_maps()
            type_map.pop(stream_id, None)
            data_map.pop(stream_id, None)




    def quic_event_received(self, event):
        # print("EVENT",event)
        if isinstance(event, StreamDataReceived):
            try:
                # logger.info(f"Server received from QUIC on stream {event.stream_id}")
                # logger.info(f"Server TCP IDs -> {self.tcp_connections.keys()}")
                # logger.info(f"Server UDP IDs -> {self.udp_connections.keys()}")

                if event.end_stream:
                    logger.info(f"Stream={event.stream_id} closed by client.")
                    self.close_this_stream(event.stream_id)

                # Forward data to the corresponding TCP connection
                elif event.stream_id in self.tcp_connections:
                    writer = self.tcp_connections[event.stream_id][1]
                    try:
                        writer.write(event.data)  # Send data over TCP
                        self._spawn(writer.drain())
                    except ConnectionResetError as e42:
                        logger.info(f"ERR in writer drain task : {e42}")
                        self.close_this_stream(event.stream_id)
                    except Exception as e43:
                        logger.info(f"ERR in writer drain task : {e43}")
                        self.close_this_stream(event.stream_id)

                # Forward data to the corresponding UDP connection
                elif event.stream_id in self.udp_connections:
                    transport, _ = self.udp_connections[event.stream_id]
                    rx = self.udp_stream_rx.get(event.stream_id)
                    if rx is None:
                        rx = _UdpReassembler()
                        self.udp_stream_rx[event.stream_id] = rx
                    for datagram in rx.feed(event.data):
                        transport.sendto(datagram)
                    now_fn = getattr(self, "_now", None)
                    loop = getattr(self, "loop", asyncio.get_event_loop())
                    self.udp_last_activity[event.stream_id] = (now_fn() if callable(now_fn) else loop.time())

                else:
                    # If we already recognized this stream as a pending connect, buffer bytes until connect completes.
                    type_map, data_map = self._pending_maps()
                    pending_type = type_map.get(event.stream_id)
                    if pending_type in ("tcp", "udp"):
                        buf = data_map.get(event.stream_id)
                        if buf is None:
                            buf = bytearray()
                            data_map[event.stream_id] = buf
                        buf.extend(event.data)
                        if len(buf) > _PENDING_MAX_BYTES:
                            logger.info("Pending buffer exceeded for stream=%s; closing stream", event.stream_id)
                            self.close_this_stream(event.stream_id)
                        return

                    parsed = parse_connect_request(event.data, parameters.quic_auth_code)
                    if parsed is None:
                        return
                    socket_type, socket_port, tail = parsed

                    # Mark as pending so any subsequent early bytes are buffered.
                    type_map[event.stream_id] = socket_type
                    if tail:
                        buf = data_map.get(event.stream_id)
                        if buf is None:
                            buf = bytearray()
                            data_map[event.stream_id] = buf
                        buf.extend(tail)
                        if len(buf) > _PENDING_MAX_BYTES:
                            logger.info("Pending buffer exceeded for stream=%s; closing stream", event.stream_id)
                            self.close_this_stream(event.stream_id)
                            return

                    logger.info("New req comes -> %sconnect,%s,%d", parameters.quic_auth_code, socket_type, socket_port)
                    if socket_type == "tcp":
                        self._spawn(self.connect_tcp(event.stream_id, socket_port))
                    else:
                        self._spawn(self.connect_udp(event.stream_id, socket_port))

            except Exception as e:
                logger.info(f"Quic event server error: {e}")

        elif isinstance(event, StreamReset):
            # Handle stream reset (client closed the stream)
            logger.info(f"Stream {event.stream_id} reset by client.")
            self.close_this_stream(event.stream_id)

        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection lost: {event.reason_phrase}")
            self.connection_lost(event.reason_phrase)


async def run_server():
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(parameters.quic_cert_filepath[0], parameters.quic_cert_filepath[1])
    configuration.max_data = parameters.quic_max_data
    configuration.max_stream_data = parameters.quic_max_stream_data
    configuration.idle_timeout = parameters.quic_idle_timeout
    configuration.max_datagram_size = parameters.quic_mtu

    # Start QUIC server
    await serve("0.0.0.0", parameters.quic_server_port, configuration=configuration, create_protocol=TunnelServerProtocol)
    logger.warning(f"Server listening for QUIC on port {parameters.quic_server_port}")

    # Keep the server running
    await asyncio.Future()  # Run forever


def handle_shutdown(signum, frame):
    logger.info("Shutting down server gracefully...")
    for protocol in active_protocols:
        protocol.close_all_tcp_connections()
        protocol.close_all_udp_connections()
        protocol.close()
    logger.info("Server shutdown complete.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    asyncio.run(run_server())
