"""All limits and detection thresholds in one place."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

DEFAULTS: dict[str, Any] = {
    # --- safety limits (loader / analyze) ---
    "max_file_mb": 50,
    "max_packets": 300_000,
    "max_seconds": 90,  # soft wall-clock cap: stop parsing, return partial results
    "subprocess_timeout": 150,  # hard cap: kill the parser process
    "memory_limit_mb": 1536,  # address-space limit for the parser process (Linux)
    "max_rows": 100_000,  # stored packet summaries for evidence tables
    "max_flows": 50_000,  # tracked TCP/UDP conversations
    "max_hosts": 10_000,
    # --- ARP / duplicate IP ---
    "arp_solicit_window": 3.0,  # a reply within this many seconds of a request is "solicited"
    "arp_spoof_min_unsolicited": 5,
    "arp_high_rate_per_min": 10,
    # --- port scan ---
    "scan_window": 60.0,
    "scan_min_ports": 15,
    "scan_min_hosts": 15,
    "scan_max_completion": 0.3,
    # --- TCP resets ---
    "rst_service_min_clients": 3,
    "rst_service_min_attempts": 5,
    "rst_midstream_min": 5,
    "rst_ttl_jump": 8,
    # --- retransmissions ---
    "retrans_min_count": 5,
    "retrans_min_rate": 0.05,
    "retrans_seq_memory": 4000,
    # --- DNS ---
    "dns_timeout": 2.0,
    "dns_min_failures": 3,
    "dns_min_fail_rate": 0.2,
    "dns_nx_min": 8,
    # --- delays ---
    "delay_factor": 3.0,
    "delay_floor_tcp": 0.3,
    "delay_floor_dns": 0.5,
    "delay_min_samples": 5,
    "delay_min_slow": 3,
    "delay_absolute_slow_tcp": 1.0,
    # --- MTU ---
    "mtu_link": 1514,
}


def make_config(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a copy of the defaults with known keys overridden."""
    cfg = deepcopy(DEFAULTS)
    for key, value in (overrides or {}).items():
        if key in cfg:
            cfg[key] = type(cfg[key])(value)
    return cfg
