# Packet-WOL Daemon

A small Linux daemon that watches network traffic for user-defined packet signatures and sends a Wake-on-LAN magic packet when a rule matches.

This project was originally inspired by a home-lab use case: waking a sleeping media server when a Roon client emits discovery traffic. The implementation is intentionally generic so you can use it for other applications too.

## What it does

- listens on a network interface with Scapy/libpcap
- applies an early BPF capture filter to reduce noise
- evaluates packets against configurable JSON rules
- sends a magic packet with `etherwake` when a rule fires
- rate-limits wake events with a cooldown
- runs cleanly as a `systemd` service

## Good use cases

- wake a Roon Core when a phone or workstation starts discovery
- wake a NAS or home server when a trusted client sends a known bootstrap packet
- wake a box only for specific apps rather than on any traffic at all

## How it works

The daemon has three layers:

1. **Capture layer** - Scapy listens on an interface using a BPF filter such as `udp port 9003 or tcp port 9332`.
2. **Rule layer** - The daemon checks source IPs, destination ports, and payload signatures such as a payload beginning with `SOOD`.
3. **Action layer** - If a rule matches and the cooldown has expired, the daemon runs `etherwake` for the configured MAC address.

## Repo layout

```text
.
├── wol_daemon.py
├── config.example.json
├── packet-wol-daemon.service
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Linux machine that can see the relevant traffic
- Python 3.10+ recommended
- `etherwake`
- root or equivalent packet-capture privileges
- a target machine with Wake-on-LAN enabled in BIOS/UEFI and OS/NIC settings

## Install from scratch

The following example uses a Raspberry Pi or other Debian-like Linux host.

### 1. Clone the repo

```bash
git clone <your-repo-url>
cd packet-wol-daemon
```

### 2. Install OS packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip etherwake tcpdump
```

### 3. Install Python dependency

```bash
sudo python3 -m pip install --break-system-packages -r requirements.txt
```

### 4. Create install directories

```bash
sudo mkdir -p /opt/packet-wol-daemon
sudo mkdir -p /etc/packet-wol-daemon
```

### 5. Copy files into place

```bash
sudo cp wol_daemon.py /opt/packet-wol-daemon/
sudo cp config.example.json /etc/packet-wol-daemon/config.json
sudo cp packet-wol-daemon.service /etc/systemd/system/
```

### 6. Edit the config

```bash
sudo nano /etc/packet-wol-daemon/config.json
```

At a minimum, update:

- `sniff_interface` - the interface that sees the client traffic
- `wake.interface` - the interface used for the magic packet
- `wake.target_mac` - the MAC address of the sleeping server
- `global_bpf` - your early capture filter
- `rules` - the packet signatures you want to wake on

## Example config concepts

### Roon-style discovery

A useful starting pattern for Roon is:

- UDP destination port `9003`
- payload starts with `SOOD`
- payload contains `Roon`

That is why the example config includes a rule named `roon-sood-discovery`.

### Tightening rules

Once you know your trusted client IPs, add them to `source_ips`. This reduces false positives a lot.

### BPF filtering

The JSON rules are not the first filter. The daemon first applies `global_bpf`, which is passed to libpcap. Keep this narrow when possible.

Examples:

```text
udp port 9003 or tcp port 9332
```

```text
(udp and dst port 9003 and src host 192.168.1.50) or (tcp and dst port 9332 and src host 192.168.1.50)
```

## Validate the config

Before running the daemon, validate the config:

```bash
sudo python3 /opt/packet-wol-daemon/wol_daemon.py --config /etc/packet-wol-daemon/config.json --check-config
```

If valid, the command exits successfully.

## Manual foreground test

Run the daemon directly first. Do not jump straight to `systemd`.

```bash
sudo python3 /opt/packet-wol-daemon/wol_daemon.py --config /etc/packet-wol-daemon/config.json
```

Then trigger the client application and watch the logs.

Expected behavior:

- matching packets are logged
- a wake event is logged
- repeated packets are suppressed during cooldown

## Verify traffic visibility with tcpdump

If nothing happens, first verify that the host can actually see the traffic:

```bash
sudo tcpdump -ni eth0 udp port 9003 or tcp port 9332
```

For payload inspection:

```bash
sudo tcpdump -ni eth0 -X udp port 9003
```

If `tcpdump` sees nothing, the daemon will see nothing too.

## Enable as a systemd service

Reload units:

```bash
sudo systemctl daemon-reload
```

Enable and start:

```bash
sudo systemctl enable --now packet-wol-daemon.service
```

Check status:

```bash
sudo systemctl status packet-wol-daemon.service
```

Watch logs live:

```bash
journalctl -u packet-wol-daemon.service -f
```

## Reboot verification

Reboot the listener host and verify the service comes back:

```bash
sudo reboot
```

After reconnecting:

```bash
sudo systemctl status packet-wol-daemon.service
journalctl -u packet-wol-daemon.service -b
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'scapy'`

Install the dependency into the same Python used by the service:

```bash
sudo python3 -m pip install --break-system-packages -r requirements.txt
```

### Manual `etherwake` test

Make sure magic packets work independently of the daemon:

```bash
sudo etherwake -i eth0 aa:bb:cc:dd:ee:ff
```

If this fails, fix Wake-on-LAN on the target first.

### Daemon runs but never matches

Common causes:

- wrong interface
- BPF filter too narrow
- source IP restrictions no longer match the client
- packet signature changed
- the listener host cannot see the traffic path you assumed

### Daemon matches but the app still fails first try

That can happen when the sleeping server resumes slower than the client retries. In that case:

- keep the wake trigger early in the flow
- reduce the wake path latency where possible
- test whether the client retries automatically or needs a second manual action

## Security notes

This daemon usually runs as root because packet capture and magic packet delivery often require elevated privileges. Keep the listener host trusted and keep rules narrow.

For a more hardened deployment you can later explore:

- Linux capabilities instead of full root
- stricter BPF filters
- source IP allowlists
- firewalling the listener host

## Publishing your own version

Before publishing:

- remove any real MAC addresses
- remove any real IP addresses
- remove any hostnames, usernames, or internal directory names
- replace them with examples in `config.example.json`
- keep your actual `config.json` out of Git

That is why `.gitignore` excludes `config.json`, `.pcap` files, and logs.

## License

MIT
