#!/usr/bin/env python3
"""
Wake-on-LAN daemon driven by packet signatures.

This service listens on a network interface, matches packets against
user-defined rules, and sends a Wake-on-LAN magic packet when a rule fires.

Designed for home-lab and media-server scenarios such as:
- waking a server when a Roon client emits discovery traffic
- waking a NAS when a known client sends a custom packet signature
- waking a machine when a specific TCP/UDP connect pattern appears

Notes:
- This daemon is intentionally conservative and heavily commented.
- Packet capture is done with Scapy. Early filtering is handled by libpcap/BPF.
- Wake delivery is delegated to the system's `etherwake` utility.
"""

from __future__ import annotations

import argparse
import binascii
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from scapy.all import AsyncSniffer, IP, IPv6, Raw, TCP, UDP  # type: ignore

LOGGER = logging.getLogger("packet-wol")
DEFAULT_LOG_LEVEL = "INFO"


class ConfigError(Exception):
    """Raised when configuration is invalid."""


@dataclass
class WakeConfig:
    interface: str
    target_mac: str
    cooldown_seconds: int = 60
    etherwake_path: str = "/usr/sbin/etherwake"
    extra_args: List[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    enabled: bool = True
    protocol: Optional[str] = None          # udp | tcp | any
    source_ips: List[str] = field(default_factory=list)
    dest_ips: List[str] = field(default_factory=list)
    source_ports: List[int] = field(default_factory=list)
    dest_ports: List[int] = field(default_factory=list)
    payload_startswith_ascii: Optional[str] = None
    payload_startswith_hex: Optional[str] = None
    payload_contains_ascii: List[str] = field(default_factory=list)
    payload_contains_hex: List[str] = field(default_factory=list)
    require_raw_payload: bool = False
    wake_enabled: bool = True
    notes: str = ""


@dataclass
class AppConfig:
    sniff_interface: str
    global_bpf: str
    wake: WakeConfig
    rules: List[Rule]
    log_level: str = DEFAULT_LOG_LEVEL


class WakeController:
    """Rate-limits wake events and sends magic packets using etherwake."""

    def __init__(self, config: WakeConfig):
        self.config = config
        self._lock = threading.Lock()
        self._last_wake_ts: float = 0.0

    def maybe_wake(self, reason: str) -> bool:
        now = time.time()
        with self._lock:
            elapsed = now - self._last_wake_ts
            if elapsed < self.config.cooldown_seconds:
                LOGGER.info(
                    "Wake suppressed by cooldown: %.1fs remaining (reason=%s)",
                    self.config.cooldown_seconds - elapsed,
                    reason,
                )
                return False

            self._send_magic_packet(reason)
            self._last_wake_ts = now
            return True

    def _send_magic_packet(self, reason: str) -> None:
        cmd = [
            self.config.etherwake_path,
            "-i",
            self.config.interface,
            *self.config.extra_args,
            self.config.target_mac,
        ]
        LOGGER.warning("Sending Wake-on-LAN packet (reason=%s): %s", reason, " ".join(cmd))
        subprocess.run(cmd, check=True)


class PacketMatcher:
    """Matches captured packets against configured rules."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules = [rule for rule in rules if rule.enabled]

    def match(self, packet: Any) -> List[Rule]:
        matched: List[Rule] = []
        for rule in self.rules:
            try:
                if self._matches_rule(packet, rule):
                    matched.append(rule)
            except Exception:
                LOGGER.exception("Rule evaluation failed for rule=%s", rule.name)
        return matched

    def _matches_rule(self, packet: Any, rule: Rule) -> bool:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return False

        transport = None
        proto_name = None
        if packet.haslayer(UDP):
            transport = packet.getlayer(UDP)
            proto_name = "udp"
        elif packet.haslayer(TCP):
            transport = packet.getlayer(TCP)
            proto_name = "tcp"

        if rule.protocol and rule.protocol != "any" and rule.protocol != proto_name:
            return False

        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        if rule.source_ips and src_ip not in rule.source_ips:
            return False
        if rule.dest_ips and dst_ip not in rule.dest_ips:
            return False

        if transport is None and (rule.source_ports or rule.dest_ports):
            return False
        if transport is not None:
            sport = int(getattr(transport, "sport", -1))
            dport = int(getattr(transport, "dport", -1))
            if rule.source_ports and sport not in rule.source_ports:
                return False
            if rule.dest_ports and dport not in rule.dest_ports:
                return False

        raw_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        if rule.require_raw_payload and not raw_bytes:
            return False

        if rule.payload_startswith_ascii is not None:
            if not raw_bytes.startswith(rule.payload_startswith_ascii.encode("utf-8")):
                return False

        if rule.payload_startswith_hex is not None:
            hex_prefix = _hex_to_bytes(rule.payload_startswith_hex)
            if not raw_bytes.startswith(hex_prefix):
                return False

        for needle in rule.payload_contains_ascii:
            if needle.encode("utf-8") not in raw_bytes:
                return False

        for needle in rule.payload_contains_hex:
            if _hex_to_bytes(needle) not in raw_bytes:
                return False

        return True


class PacketWolDaemon:
    """Main application class."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.wake_controller = WakeController(config.wake)
        self.matcher = PacketMatcher(config.rules)
        self.sniffer: Optional[AsyncSniffer] = None
        self.stop_event = threading.Event()

    def start(self) -> None:
        LOGGER.info("Starting packet listener on interface=%s", self.config.sniff_interface)
        LOGGER.info("Using global BPF filter: %s", self.config.global_bpf)
        self.sniffer = AsyncSniffer(
            iface=self.config.sniff_interface,
            filter=self.config.global_bpf,
            prn=self._handle_packet,
            store=False,
        )
        self.sniffer.start()
        LOGGER.info("Packet listener started")

    def stop(self) -> None:
        self.stop_event.set()
        if self.sniffer is not None:
            LOGGER.info("Stopping packet listener")
            self.sniffer.stop()
            self.sniffer = None

    def run_forever(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        finally:
            self.stop()

    def _handle_packet(self, packet: Any) -> None:
        matches = self.matcher.match(packet)
        if not matches:
            return

        summary = packet.summary()
        for rule in matches:
            LOGGER.info("Rule matched: %s | packet=%s", rule.name, summary)
            if rule.wake_enabled:
                self.wake_controller.maybe_wake(reason=rule.name)
            else:
                LOGGER.info("Rule matched but wake is disabled: %s", rule.name)


def _hex_to_bytes(value: str) -> bytes:
    cleaned = value.strip().replace(" ", "").replace(":", "")
    if len(cleaned) % 2 != 0:
        raise ConfigError(f"Invalid hex string length: {value!r}")
    try:
        return binascii.unhexlify(cleaned)
    except binascii.Error as exc:
        raise ConfigError(f"Invalid hex string: {value!r}") from exc


def _validate_mac(value: str) -> str:
    parts = value.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ConfigError(f"Invalid MAC address: {value!r}")
    try:
        bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise ConfigError(f"Invalid MAC address: {value!r}") from exc
    return value.lower()


def load_config(path: str) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")

    data = json.loads(config_path.read_text(encoding="utf-8"))

    try:
        wake_block = data["wake"]
        wake = WakeConfig(
            interface=str(wake_block["interface"]),
            target_mac=_validate_mac(str(wake_block["target_mac"])),
            cooldown_seconds=int(wake_block.get("cooldown_seconds", 60)),
            etherwake_path=str(wake_block.get("etherwake_path", "/usr/sbin/etherwake")),
            extra_args=list(wake_block.get("extra_args", [])),
        )

        rules: List[Rule] = []
        for item in data.get("rules", []):
            rules.append(
                Rule(
                    name=str(item["name"]),
                    enabled=bool(item.get("enabled", True)),
                    protocol=item.get("protocol"),
                    source_ips=list(item.get("source_ips", [])),
                    dest_ips=list(item.get("dest_ips", [])),
                    source_ports=[int(x) for x in item.get("source_ports", [])],
                    dest_ports=[int(x) for x in item.get("dest_ports", [])],
                    payload_startswith_ascii=item.get("payload_startswith_ascii"),
                    payload_startswith_hex=item.get("payload_startswith_hex"),
                    payload_contains_ascii=list(item.get("payload_contains_ascii", [])),
                    payload_contains_hex=list(item.get("payload_contains_hex", [])),
                    require_raw_payload=bool(item.get("require_raw_payload", False)),
                    wake_enabled=bool(item.get("wake_enabled", True)),
                    notes=str(item.get("notes", "")),
                )
            )

        if not rules:
            raise ConfigError("At least one rule must be defined")

        app_config = AppConfig(
            sniff_interface=str(data["sniff_interface"]),
            global_bpf=str(data["global_bpf"]),
            wake=wake,
            rules=rules,
            log_level=str(data.get("log_level", DEFAULT_LOG_LEVEL)).upper(),
        )
        validate_config(app_config)
        return app_config
    except KeyError as exc:
        raise ConfigError(f"Missing required config key: {exc.args[0]}") from exc


def validate_config(config: AppConfig) -> None:
    if not config.sniff_interface:
        raise ConfigError("sniff_interface must not be empty")
    if not config.global_bpf:
        raise ConfigError("global_bpf must not be empty")
    if config.wake.cooldown_seconds < 0:
        raise ConfigError("wake.cooldown_seconds must be >= 0")
    if not config.wake.interface:
        raise ConfigError("wake.interface must not be empty")
    if not config.wake.etherwake_path:
        raise ConfigError("wake.etherwake_path must not be empty")

    for rule in config.rules:
        if rule.protocol not in (None, "udp", "tcp", "any"):
            raise ConfigError(f"Rule {rule.name!r} has invalid protocol: {rule.protocol!r}")
        if rule.payload_startswith_hex is not None:
            _hex_to_bytes(rule.payload_startswith_hex)
        for item in rule.payload_contains_hex:
            _hex_to_bytes(item)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Packet-triggered Wake-on-LAN daemon")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the config file and exit",
    )
    return parser


def install_signal_handlers(app: PacketWolDaemon) -> None:
    def _handler(signum: int, _frame: Any) -> None:
        LOGGER.info("Received signal %s, shutting down", signum)
        app.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main() -> int:
    args = build_arg_parser().parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.log_level)

    if args.check_config:
        LOGGER.info("Config is valid")
        return 0

    app = PacketWolDaemon(config)
    install_signal_handlers(app)

    try:
        app.run_forever()
        return 0
    except subprocess.CalledProcessError as exc:
        LOGGER.error("Failed to send Wake-on-LAN packet: %s", exc)
        return 1
    except PermissionError as exc:
        LOGGER.error("Permission error. Raw packet capture usually requires root or packet capabilities: %s", exc)
        return 1
    except KeyboardInterrupt:
        LOGGER.info("Interrupted by user")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
