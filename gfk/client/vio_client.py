from scapy.all import AsyncSniffer, IP, TCP, Raw, conf
import asyncio
import parameters
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VioClient")

vps_ip = parameters.vps_ip
vio_tcp_server_port = parameters.vio_tcp_server_port
vio_tcp_client_port = parameters.vio_tcp_client_port
vio_udp_client_port = parameters.vio_udp_client_port
quic_local_ip = parameters.quic_local_ip
quic_client_port = parameters.quic_client_port
tcp_flags = getattr(parameters, 'tcp_flags', 'AP')

tcp_options=[
    ('MSS', 1280),
    ('WScale', 8),
    ('SAckOK', ''),
]

basepkt = None
skt = None


def _ensure_sender():
    """
    Initialize the scapy L3 sender lazily.

    This allows importing the module (and running unit tests) without root.
    """
    global basepkt, skt
    if basepkt is None:
        logger.info("Using L3 socket for violated TCP packets")
        basepkt = IP(dst=vps_ip) / TCP(
            sport=vio_tcp_client_port,
            dport=vio_tcp_server_port,
            seq=0,
            flags=tcp_flags,
            ack=0,
            options=tcp_options,
        ) / Raw(load=b"")
    if skt is None:
        skt = conf.L3socket()


async def _close_and_abort_transport(transport) -> None:
    """
    Best-effort close/abort a datagram transport.

    This keeps the cleanup sequence in one place so it stays consistent and
    becomes easier to unit-test.
    """
    try:
        transport.close()
    except Exception:
        pass
    await asyncio.sleep(0.5)
    try:
        transport.abort()
        logger.info("aborting transport ...")
    except Exception:
        pass
    await asyncio.sleep(1.5)
    logger.info("vio inner finished")


async def async_sniff_realtime(qu1):
    logger.info("sniffer started")
    try:
        def process_packet(packet):
            # Check flags using 'in' to handle different flag orderings (AP vs PA)
            flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ""
            if (
                packet.haslayer(TCP)
                and packet[IP].src == vps_ip
                and packet[TCP].sport == vio_tcp_server_port
                and "A" in flags
                and "P" in flags
            ):
                data1 = packet[TCP].load
                qu1.put_nowait(data1)

        sniffer = AsyncSniffer(
            prn=process_packet,
            filter=f"tcp and src host {vps_ip} and src port {vio_tcp_server_port}",
            store=False,
        )
        sniffer.start()
        return sniffer
    except Exception as e:
        logger.info(f"sniff Generic error: {e}....")
        raise  # Re-raise so caller knows sniffer failed


async def forward_vio_to_quic(qu1, transport):
    logger.info(f"Task vio to Quic started")
    addr = (quic_local_ip, quic_client_port)
    try:
        while True:
            data = await qu1.get()
            if data is None:
                break
            transport.sendto(data, addr)
    except Exception as e:
        logger.info(f"Error forwarding vio to Quic: {e}")
    finally:
        logger.info(f"Task vio to Quic Ended.")


def send_to_violated_TCP(binary_data):
    _ensure_sender()
    new_pkt = basepkt.copy()
    new_pkt[TCP].load = binary_data
    skt.send(new_pkt)


async def forward_quic_to_vio(protocol):
    logger.info(f"Task QUIC to vio started")
    try:
        while True:
            data = await protocol.queue.get()
            if data is None:
                break
            send_to_violated_TCP(data)
    except Exception as e:
        logger.info(f"Error forwarding QUIC to vio: {e}")
    finally:
        logger.info(f"Task QUIC to vio Ended.")


async def start_udp_server(qu1):
    while True:
        transport = None
        task1 = None
        task2 = None
        try:
            logger.warning(f"listen quic:{vio_udp_client_port} -> violated tcp:{vio_tcp_server_port}")
            loop = asyncio.get_event_loop()
            transport, udp_protocol = await loop.create_datagram_endpoint(
                lambda: UdpProtocol(),
                local_addr=('0.0.0.0', vio_udp_client_port)
            )
            task1 = asyncio.create_task(forward_quic_to_vio(udp_protocol))
            task2 = asyncio.create_task(forward_vio_to_quic(qu1, transport))

            while True:
                await asyncio.sleep(0.02)
                if udp_protocol.has_error:
                    if task1 is not None:
                        task1.cancel()
                    if task2 is not None:
                        task2.cancel()
                    await asyncio.sleep(1)
                    logger.info(f"all task cancelled")
                    break

        except Exception as e:
            logger.info(f"vioclient ERR: {e}")
        finally:
            if transport is not None:
                await _close_and_abort_transport(transport)


class UdpProtocol:
    def __init__(self):
        self.transport = None
        self.has_error = False
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        logger.info("NEW DGRAM listen created")
        logger.info(transport.get_extra_info('socket'))
        self.transport = transport

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)

    def error_received(self, exc):
        logger.info(f"UDP error received: {exc}")
        self.has_error = True
        if self.transport:
            self.transport.close()
            logger.info("UDP transport closed")

    def connection_lost(self, exc):
        logger.info(f"UDP lost. {exc}")
        self.has_error = True
        if self.transport:
            self.transport.close()
            logger.info("UDP transport closed")


async def run_vio_client():
    sniffer = None
    try:
        qu1 = asyncio.Queue()
        sniffer = await async_sniff_realtime(qu1)

        await asyncio.gather(start_udp_server(qu1), return_exceptions=True)

        logger.info("end ?")
    except SystemExit as e:
        logger.info(f"Caught SystemExit: {e}")
    except asyncio.CancelledError as e:
        logger.info(f"cancelling error: {e}")
    except ConnectionError as e:
        logger.info(f"Connection error: {e}")
    except Exception as e:
        logger.info(f"Generic error: {e}")
    finally:
        if sniffer is not None:
            sniffer.stop()
            logger.info("stop sniffer")


if __name__ == "__main__":
    asyncio.run(run_vio_client())
