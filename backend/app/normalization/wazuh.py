from typing import Any


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _nested_get(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if value is not None
    }


def normalize_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    win_eventdata = _nested_get(data, "win", "eventdata") or {}

    normalized = {
        "title": _first_present(
            rule.get("description"),
            alert.get("full_log"),
            "Wazuh alert",
        ),
        "source": "wazuh",
        "source_alert_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_groups": rule.get("groups", []),
        "host": _first_present(
            agent.get("name"),
            data.get("hostname"),
            win_eventdata.get("computer"),
        ),
        "agent_id": agent.get("id"),
        "agent_ip": agent.get("ip"),
        "ip": _first_present(
            data.get("srcip"),
            data.get("src_ip"),
            data.get("source_ip"),
            data.get("dstip"),
            data.get("dest_ip"),
            data.get("src_ip_addr"),
            win_eventdata.get("ipAddress"),
            win_eventdata.get("sourceIp"),
        ),
        "user": _first_present(
            data.get("srcuser"),
            data.get("user"),
            data.get("dstuser"),
            data.get("dst_user"),
            win_eventdata.get("targetUserName"),
            win_eventdata.get("subjectUserName"),
        ),
        "domain": _first_present(
            data.get("domain"),
            data.get("hostname"),
            data.get("url"),
            win_eventdata.get("targetDomainName"),
        ),
        "process": _first_present(
            data.get("process"),
            data.get("program_name"),
            win_eventdata.get("processName"),
            win_eventdata.get("image"),
        ),
        "location": alert.get("location"),
        "decoder": decoder.get("name"),
        "full_log": alert.get("full_log"),
        "wazuh": alert,
    }

    return _compact(normalized)
