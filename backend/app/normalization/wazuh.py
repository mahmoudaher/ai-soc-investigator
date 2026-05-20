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


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _lower_values(*values: Any) -> set[str]:
    lowered: set[str] = set()
    for value in values:
        for item in _as_list(value):
            if item is not None:
                lowered.add(str(item).lower())
    return lowered


def _event_id(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _classify_event(
    *,
    decoder_name: str | None,
    rule_groups: list[Any],
    rule_description: Any,
    event_id: str | None,
    provider_name: Any,
    sca_check: dict[str, Any],
    location: Any,
) -> tuple[str | None, str | None]:
    tokens = _lower_values(
        decoder_name,
        rule_groups,
        rule_description,
        provider_name,
        location,
    )
    description = str(rule_description or "").lower()
    provider = str(provider_name or "").lower()

    if "sca" in tokens or decoder_name == "sca" or sca_check:
        result = str(sca_check.get("result") or "").strip().lower()
        if result in {"failed", "fail"}:
            return "configuration", "sca_policy_failed"
        if result in {"passed", "pass"}:
            return "configuration", "sca_policy_passed"
        if result in {"not applicable", "not_applicable", "not-applicable"}:
            return "configuration", "sca_policy_not_applicable"
        return "configuration", "sca_policy_check"

    if event_id == "4625" or "authentication_failed" in tokens:
        return "authentication", "failed_login"
    if event_id == "4624" or "authentication_success" in tokens:
        return "authentication", "successful_login"
    if event_id == "4672":
        return "privilege", "special_privileges_assigned"
    if event_id == "7040":
        return "configuration", "service_config_change"
    if event_id == "7045":
        return "configuration", "new_service_created"

    is_sysmon = "sysmon" in provider or "sysmon" in tokens
    if event_id == "4688" or (is_sysmon and event_id == "1"):
        return "process", "process_creation"
    if is_sysmon and event_id == "3":
        return "network", "network_connection"

    if "syscheck" in tokens or "fim" in tokens:
        return "file", "file_modified"
    if (
        "malware" in tokens
        or "virus" in tokens
        or "defender" in tokens
        or "malware" in description
        or "virus" in description
        or "defender" in description
    ):
        return "malware", "malware_detected"
    if "web" in tokens or "web_attack" in tokens or "attack" in description:
        return "web", "web_attack"
    if "policy_changed" in tokens or "configuration" in tokens:
        return "configuration", "configuration_change"

    return None, None


def normalize_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    decoder_name = decoder.get("name")
    rule_groups = rule.get("groups", [])
    win_eventdata = _nested_get(data, "win", "eventdata") or {}
    win_system = _nested_get(data, "win", "system") or {}
    sca = data.get("sca") if isinstance(data.get("sca"), dict) else {}
    sca_check = sca.get("check") if isinstance(sca.get("check"), dict) else {}
    event_id = _event_id(win_system.get("eventID"))
    event_kind, event_action = _classify_event(
        decoder_name=decoder_name,
        rule_groups=rule_groups,
        rule_description=rule.get("description"),
        event_id=event_id,
        provider_name=win_system.get("providerName"),
        sca_check=sca_check,
        location=alert.get("location"),
    )

    normalized = {
        "title": _first_present(
            rule.get("description"),
            sca_check.get("title"),
            win_system.get("message"),
            alert.get("full_log"),
            "Wazuh alert",
        ),
        "source": "wazuh",
        "source_alert_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_groups": rule_groups,
        "event_kind": event_kind,
        "event_action": event_action,
        "host": _first_present(
            agent.get("name"),
            data.get("hostname"),
            win_system.get("computer"),
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
            win_eventdata.get("destinationIp"),
        ),
        "source_ip": _first_present(
            data.get("srcip"),
            data.get("src_ip"),
            data.get("source_ip"),
            win_eventdata.get("ipAddress"),
            win_eventdata.get("sourceIp"),
        ),
        "destination_ip": _first_present(
            data.get("dstip"),
            data.get("dest_ip"),
            data.get("destination_ip"),
            win_eventdata.get("destinationIp"),
            win_eventdata.get("destIp"),
        ),
        "source_port": _first_present(
            data.get("srcport"),
            data.get("src_port"),
            win_eventdata.get("ipPort"),
            win_eventdata.get("sourcePort"),
        ),
        "destination_port": _first_present(
            data.get("dstport"),
            data.get("dest_port"),
            win_eventdata.get("destinationPort"),
            win_eventdata.get("destPort"),
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
            win_eventdata.get("subjectDomainName"),
        ),
        "process": _first_present(
            data.get("process"),
            data.get("program_name"),
            win_eventdata.get("processName"),
            win_eventdata.get("image"),
            win_eventdata.get("parentImage"),
            win_eventdata.get("commandLine"),
        ),
        "process_id": _first_present(
            data.get("pid"),
            data.get("process_id"),
            win_eventdata.get("processId"),
            win_system.get("processID"),
        ),
        "parent_process": _first_present(
            win_eventdata.get("parentImage"),
            win_eventdata.get("parentProcessName"),
        ),
        "command_line": _first_present(
            win_eventdata.get("commandLine"),
            data.get("command"),
        ),
        "service_name": _first_present(
            win_eventdata.get("serviceName"),
            win_eventdata.get("param1"),
        ),
        "service_image": _first_present(
            win_eventdata.get("imagePath"),
            win_eventdata.get("serviceFileName"),
        ),
        "service_start_type": _first_present(
            win_eventdata.get("startType"),
            win_eventdata.get("param3"),
        ),
        "windows_event_id": event_id,
        "windows_provider": win_system.get("providerName"),
        "windows_channel": win_system.get("channel"),
        "windows_computer": win_system.get("computer"),
        "logon_type": win_eventdata.get("logonType"),
        "authentication_package": win_eventdata.get("authenticationPackageName"),
        "failure_status": _first_present(
            win_eventdata.get("status"),
            win_eventdata.get("subStatus"),
        ),
        "sca_policy": sca.get("policy"),
        "sca_scan_id": sca.get("scan_id"),
        "sca_check_id": sca_check.get("id"),
        "sca_check_title": sca_check.get("title"),
        "sca_result": sca_check.get("result"),
        "sca_reason": sca_check.get("reason"),
        "registry": sca_check.get("registry"),
        "location": alert.get("location"),
        "decoder": decoder_name,
        "full_log": alert.get("full_log"),
        "wazuh": alert,
    }

    return _compact(normalized)
