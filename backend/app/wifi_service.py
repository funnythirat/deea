import datetime
import logging
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def get_connected_interface_info() -> Dict[str, Any]:
    """Parse netsh wlan show interfaces to get active Wi-Fi connection info."""
    info: Dict[str, Any] = {
        "interface": "",
        "state": "disconnected",
        "ssid": "",
        "bssid": "",
        "signal": 0,
        "authentication": "Unknown",
        "encryption": "Unknown",
        "band": "",
        "channel": "",
        "radioType": "",
        "hasPassword": True,
    }
    if platform.system().lower() != "windows":
        return info

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=5,
        )
        if res.returncode != 0 or not res.stdout:
            return info

        for raw_line in res.stdout.splitlines():
            line = raw_line.strip()
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key, val = key.strip(), val.strip()

            if key == "Name":
                if not info["interface"]:
                    info["interface"] = val
            elif key == "State":
                info["state"] = val.lower()
            elif key == "SSID":
                info["ssid"] = val
            elif key == "AP BSSID":
                info["bssid"] = val
            elif key == "Signal":
                info["signal"] = int(re.sub(r"[^\d]", "", val) or 0)
            elif key == "Authentication":
                info["authentication"] = val
            elif key in ("Cipher", "Encryption"):
                info["encryption"] = val
            elif key == "Band":
                info["band"] = val
            elif key == "Channel":
                info["channel"] = val
            elif key == "Radio type":
                info["radioType"] = val

        auth = info["authentication"].lower()
        enc = info["encryption"].lower()
        if "open" in auth or "none" in enc:
            info["hasPassword"] = False
        else:
            info["hasPassword"] = True

    except Exception as exc:
        logger.warning("Failed to query netsh interfaces: %s", exc)

    return info


def scan_local_wifi() -> Dict[str, Any]:
    """Scan real nearby Wi-Fi networks using netsh and return structured data."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    connected_info = get_connected_interface_info()
    connected_ssid = connected_info.get("ssid", "")

    if platform.system().lower() != "windows":
        return {
            "success": False,
            "message": "Direct Wi-Fi scanning via netsh is supported on Windows hosts.",
            "scanTime": now_iso,
            "interface": connected_info.get("interface", "N/A"),
            "connected": connected_info if connected_info.get("state") == "connected" else None,
            "availableNetworks": [],
            "count": 0,
        }

    networks_by_ssid: Dict[str, Dict[str, Any]] = {}

    # Query 1: Mode=BSSID for detailed signal, band, channel, BSSID
    try:
        res_bssid = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=8,
        )
        if res_bssid.returncode == 0 and res_bssid.stdout:
            current_net: Optional[Dict[str, Any]] = None
            for raw_line in res_bssid.stdout.splitlines():
                line = raw_line.strip()
                m_ssid = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
                if m_ssid:
                    if current_net and current_net["ssid"]:
                        networks_by_ssid[current_net["ssid"]] = current_net
                    raw_name = m_ssid.group(1).strip()
                    ssid_name = raw_name if raw_name else "(Hidden Network)"
                    current_net = {
                        "ssid": ssid_name,
                        "authentication": "WPA2-Personal",
                        "encryption": "CCMP",
                        "signal": 70,
                        "radioType": "802.11ac",
                        "band": "2.4 GHz",
                        "channel": "6",
                        "bssid": "",
                        "hasPassword": True,
                        "isConnected": False,
                    }
                    continue

                if current_net:
                    if line.startswith("Authentication"):
                        val = line.split(":", 1)[1].strip()
                        current_net["authentication"] = val
                        current_net["hasPassword"] = (
                            "open" not in val.lower() and "none" not in val.lower()
                        )
                    elif line.startswith("Encryption"):
                        val = line.split(":", 1)[1].strip()
                        current_net["encryption"] = val
                        if "none" in val.lower():
                            current_net["hasPassword"] = False
                    elif line.startswith("Signal"):
                        val = line.split(":", 1)[1].strip()
                        current_net["signal"] = int(re.sub(r"[^\d]", "", val) or 0)
                    elif line.startswith("Radio type"):
                        current_net["radioType"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Band"):
                        current_net["band"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Channel"):
                        current_net["channel"] = line.split(":", 1)[1].strip()
                    elif line.startswith("BSSID 1"):
                        current_net["bssid"] = line.split(":", 1)[1].strip()

            if current_net and current_net["ssid"]:
                networks_by_ssid[current_net["ssid"]] = current_net
    except Exception as exc:
        logger.warning("Error running netsh networks mode=bssid: %s", exc)

    # Query 2: Standard netsh wlan show networks to catch any additional visible SSIDs
    try:
        res_std = subprocess.run(
            ["netsh", "wlan", "show", "networks"],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=5,
        )
        if res_std.returncode == 0 and res_std.stdout:
            curr_ssid = ""
            for raw_line in res_std.stdout.splitlines():
                line = raw_line.strip()
                m_ssid = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
                if m_ssid:
                    raw_name = m_ssid.group(1).strip()
                    curr_ssid = raw_name if raw_name else "(Hidden Network)"
                    if curr_ssid and curr_ssid not in networks_by_ssid:
                        networks_by_ssid[curr_ssid] = {
                            "ssid": curr_ssid,
                            "authentication": "WPA2-Personal",
                            "encryption": "CCMP",
                            "signal": 75,
                            "radioType": "802.11ac",
                            "band": "2.4 GHz",
                            "channel": "1",
                            "bssid": "",
                            "hasPassword": True,
                            "isConnected": False,
                        }
                    continue
                if curr_ssid and curr_ssid in networks_by_ssid:
                    if line.startswith("Authentication"):
                        val = line.split(":", 1)[1].strip()
                        networks_by_ssid[curr_ssid]["authentication"] = val
                        networks_by_ssid[curr_ssid]["hasPassword"] = (
                            "open" not in val.lower() and "none" not in val.lower()
                        )
                    elif line.startswith("Encryption"):
                        val = line.split(":", 1)[1].strip()
                        networks_by_ssid[curr_ssid]["encryption"] = val
                        if "none" in val.lower():
                            networks_by_ssid[curr_ssid]["hasPassword"] = False
    except Exception as exc:
        logger.warning("Error running netsh show networks: %s", exc)

    # If currently connected network is known, ensure it's in the list and marked connected
    if connected_ssid:
        if connected_ssid in networks_by_ssid:
            networks_by_ssid[connected_ssid]["isConnected"] = True
            if connected_info.get("signal"):
                networks_by_ssid[connected_ssid]["signal"] = connected_info["signal"]
            if connected_info.get("bssid"):
                networks_by_ssid[connected_ssid]["bssid"] = connected_info["bssid"]
        else:
            networks_by_ssid[connected_ssid] = {
                "ssid": connected_ssid,
                "authentication": connected_info.get("authentication", "WPA2-Personal"),
                "encryption": connected_info.get("encryption", "CCMP"),
                "signal": connected_info.get("signal", 100),
                "radioType": connected_info.get("radioType", "802.11ac"),
                "band": connected_info.get("band", "2.4 GHz"),
                "channel": connected_info.get("channel", "9"),
                "bssid": connected_info.get("bssid", ""),
                "hasPassword": connected_info.get("hasPassword", True),
                "isConnected": True,
            }

    network_list = list(networks_by_ssid.values())
    network_list.sort(key=lambda n: (1 if n.get("isConnected") else 0, n.get("signal", 0)), reverse=True)

    return {
        "success": True,
        "scanTime": now_iso,
        "interface": connected_info.get("interface", "Wi-Fi"),
        "connected": connected_info if connected_info.get("state") == "connected" else None,
        "availableNetworks": network_list,
        "count": len(network_list),
    }
