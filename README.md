# paqctl (GFK-only)

`paqctl` is a small installer/manager for **GFW-knocker (GFK)**: a tunnel built from **Violated TCP + QUIC** that can do **TCP/UDP port forwarding** through censorship/DPI-heavy networks.

This repository’s `paqctl.sh` has been simplified to **GFK only**.

## How it works (high level)

- **System A (client/relay)** runs the GFK client and listens on local/public ports you choose.
- **System B (server)** runs the GFK server and forwards those streams to local ports on B.

For UDP forwarding (example: WireGuard):

```
WG client  --->  A_PUBLIC_IP:51830  ==GFK tunnel==>  B:51820  --->  WireGuard server
```

## Requirements

- Linux on both sides
- Root access (GFK uses raw sockets / sniffing)
- Open ports:
  - On **System B**: inbound TCP on `GFK_VIO_PORT` (default `45000`)
  - On **System A**: inbound UDP on whatever **your forwarded UDP listen port** is (example `51830`)

## Install

### System B (server)

Run on **System B**:

```bash
curl -fsSL https://raw.githubusercontent.com/hosseini92/paqctl/main/paqctl.sh | sudo bash
sudo paqctl config
sudo paqctl start
sudo paqctl status
```

Choose **role = Server** and note the values you pick (especially **VIO port**, **QUIC port**, **Auth code**).

### System A (client/relay)

Run on **System A**:

```bash
curl -fsSL https://raw.githubusercontent.com/hosseini92/paqctl/main/paqctl.sh | sudo bash
sudo paqctl config
sudo paqctl start
sudo paqctl status
```

Choose **role = Client**, enter **System B IP**, and set your **UDP mappings** when prompted.

## Configure UDP port forwarding

In the client wizard you’ll be asked for:

- **UDP port mappings**: `local_listen_port:server_target_port` (comma-separated)

Example (WireGuard):

- Client (System A) listens on UDP `51830`
- Server (System B) receives on UDP `51820` (where your WG server listens on B)

So on **System A** set:

```
51830:51820
```

After changing config:

```bash
sudo paqctl restart
```

## Updating IPs / changing config

Re-run:

```bash
sudo paqctl config
sudo paqctl restart
```

This regenerates `/opt/paqctl/gfk/parameters.py` from `/opt/paqctl/settings.conf`.

## iptables notes (server role)

When running as **server**, `paqctl` applies iptables rules for the **VIO TCP port** (default `45000`) to avoid conntrack and kernel interference (NOTRACK + DROP + drop outbound RST).  
It does **not** automatically open your forwarded UDP ports; you must allow those in your own firewall if needed.

## Multiple clients

This repo’s GFK server has been updated to support **multiple simultaneous clients** by maintaining a separate internal QUIC/UDP session per client.

Note: clients are identified by **source IP + source port** of the violated TCP packets. If you have multiple clients behind the same NAT using the same source port, set a unique `vio_tcp_client_port` per client.

## Commands

```bash
sudo paqctl install        # install / setup
sudo paqctl config         # reconfigure (wizard)
sudo paqctl start|stop|restart
sudo paqctl status
sudo paqctl info
sudo paqctl logs
sudo paqctl uninstall
```

## Files / paths

- `paqctl.sh`: installer + manager (GFK-only)
- `/opt/paqctl/settings.conf`: saved config
- `/opt/paqctl/gfk/parameters.py`: generated runtime config
- `/var/log/gfk-backend.log`: service logs (or `journalctl -u paqctl.service`)

## License

MIT. See `LICENSE`.

