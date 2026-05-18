import os
import urllib.parse
import urllib.request
import ssl
import json
import time
import threading
from datetime import timedelta
from dynatrace_extension import Extension, Status, StatusValue, DtEventType


# ─── SSL CONTEXT ──────────────────────────────────────────────────────────────
NO_VERIFY_CTX = ssl.create_default_context()
NO_VERIFY_CTX.check_hostname = False
NO_VERIFY_CTX.verify_mode    = ssl.CERT_NONE

# ─── TOKEN CACHE ──────────────────────────────────────────────────────────────
_token_cache = {}
_token_lock  = threading.Lock()

# ─── ALARM CACHE (moid -> title) ──────────────────────────────────────────────
_last_known_alarms      = {}  # {host: {moid: title}}
_last_known_alarms_lock = threading.Lock()

# ─── ENTITY CONFIRMED CACHE ───────────────────────────────────────────────────
_entity_confirmed      = set()
_entity_confirmed_lock = threading.Lock()

# ─── STORAGE ──────────────────────────────────────────────────────────────────
STORAGE_DIR = "/var/lib/dynatrace/remotepluginmodule/storage/cisco_intersight"


def get_token(base_url: str, client_id: str, client_secret: str, proxy: str = "") -> str:
    import base64
    with _token_lock:
        now    = time.time()
        cached = _token_cache.get(base_url)
        if cached and now < cached["expires_at"] - 60:
            return cached["token"]

        url     = f"{base_url}/iam/token"
        payload = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
        creds   = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type":  "application/x-www-form-urlencoded",
                "Authorization": f"Basic {creds}",
            },
            method="POST"
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": proxy} if proxy else {}),
            urllib.request.HTTPSHandler(context=NO_VERIFY_CTX)
        )
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read())
            _token_cache[base_url] = {
                "token":      data["access_token"],
                "expires_at": now + data.get("expires_in", 3600)
            }
            return _token_cache[base_url]["token"]


def get_active_alarms(base_url: str, token: str,
                      proxy: str = "", severity_filter: str = "") -> list:
    base_filter = "Acknowledge eq 'None' and Suppressed eq false"
    if severity_filter:
        full_filter = f"({severity_filter}) and {base_filter}"
    else:
        full_filter = f"Severity ne 'Cleared' and {base_filter}"

    params = urllib.parse.urlencode({
        "$filter": full_filter,
        "$select": "Moid,Name,Severity,Description,Code,AffectedMoDisplayName,AffectedMoType,AffectedMo,AccountMoid",
        "$top":    "1000",
    })
    url = f"{base_url}/api/v1/cond/Alarms?{params}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="GET"
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": proxy} if proxy else {}),
        urllib.request.HTTPSHandler(context=NO_VERIFY_CTX)
    )
    with opener.open(req, timeout=15) as resp:
        return json.loads(resp.read()).get("Results", [])


def extract_hostname(base_url: str, alarm: dict) -> str:
    for key in ("AffectedMo", "RegisteredDevice"):
        obj = alarm.get(key)
        if isinstance(obj, dict):
            link = obj.get("link", "")
            if link:
                parsed = urllib.parse.urlparse(link)
                if parsed.hostname:
                    return parsed.hostname
    return base_url.replace("https://", "").replace("http://", "")


def build_severity_filter(endpoint: dict) -> str:
    filters = []
    if endpoint.get("enable_critical", True):
        filters.append("Severity eq 'Critical'")
    if endpoint.get("enable_warning", True):
        filters.append("Severity eq 'Warning'")
    if endpoint.get("enable_info", False):
        filters.append("Severity eq 'Info'")
    return " or ".join(filters) if filters else ""


def get_enabled_severities(endpoint: dict) -> set:
    enabled = set()
    if endpoint.get("enable_critical", True):
        enabled.add("Critical")
    if endpoint.get("enable_warning", True):
        enabled.add("Warning")
    if endpoint.get("enable_info", False):
        enabled.add("Info")
    return enabled


def safe_host(host: str) -> str:
    return host.replace(".", "_").replace(":", "_").replace("/", "_")


def save_alarms_to_file(host: str, alarms: dict):
    """Save {moid: title} dict to file asynchronously."""
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_host(host)}_alarms.json"
        with open(path, "w") as f:
            json.dump(alarms, f)
    except Exception:
        pass


def load_alarms_from_file(host: str) -> dict:
    """Load {moid: title} dict from file."""
    try:
        path = f"{STORAGE_DIR}/{safe_host(host)}_alarms.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


class ExtensionImpl(Extension):

    def initialize(self):
        self.logger.info("initialize called")
        config = self.get_activation_config()

        # Load alarm cache from files on startup
        for endpoint in config.get("endpoints", []):
            host   = endpoint["url"].rstrip("/").replace("https://", "").replace("http://", "")
            alarms = load_alarms_from_file(host)
            if alarms:
                with _last_known_alarms_lock:
                    _last_known_alarms[host] = alarms
                self.logger.info(f"Loaded {len(alarms)} cached alarms for {host}")

        # Schedule polls per endpoint
        for endpoint in config.get("endpoints", []):
            if not endpoint.get("enable_alarms", True):
                continue
            poll_minutes = int(endpoint.get("poll_interval", 5))
            host         = endpoint["url"].rstrip("/").replace("https://", "").replace("http://", "")
            self.logger.info(f"Scheduling poll for {host} every {poll_minutes} minutes")
            self.schedule(
                lambda ep=endpoint: self._poll_endpoint(ep),
                timedelta(minutes=poll_minutes)
            )

    def query(self):
        pass

    def _get_entity_selector(self, host: str):
        with _entity_confirmed_lock:
            if host in _entity_confirmed:
                return f'type(cisco:intersight_domain),intersight_host("{host}")'
            else:
                _entity_confirmed.add(host)
                return None

    def _build_event_title(self, alarm: dict) -> str:
        moid        = alarm.get("Moid", "")
        name        = alarm.get("Name", "Unknown")
        severity    = alarm.get("Severity", "Info")
        description = alarm.get("Description", "No details")
        return f"[{severity}] {name}: {description[:80]} [{moid}]"

    def _send_alarm_event(self, alarm: dict, base_url: str,
                          alarm_timeout: int, entity_selector: str = None,
                          is_refresh: bool = False):
        moid        = alarm.get("Moid", "")
        name        = alarm.get("Name", "Unknown")
        severity    = alarm.get("Severity", "Info")
        description = alarm.get("Description", "No details")
        code        = alarm.get("Code", "N/A")
        affected_mo = alarm.get("AffectedMoDisplayName") or alarm.get("AffectedMoType") or "N/A"
        alarm_host  = extract_hostname(base_url, alarm)
        title       = self._build_event_title(alarm)

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=title,
            timeout=alarm_timeout,
            entity_selector=entity_selector,
            properties={
                "dt.event.correlation_tag": f"intersight-{moid}",
                "Alarm Name":               name,
                "Severity":                 severity,
                "Fault Code":               code,
                "Description":              description,
                "Affected Object":          affected_mo,
                "Intersight Host":          alarm_host,
                "Intersight MOID":          moid,
            }
        )
        if is_refresh:
            self.logger.info(f"Refreshed: {name} severity={severity} moid={moid}")
        else:
            self.logger.info(f"Event sent: {name} severity={severity} moid={moid}")

    def _send_unreachable_event(self, host: str, error: str,
                                alarm_timeout: int, entity_selector: str = None):
        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=f"[Critical] Intersight host unreachable: {host}",
            timeout=alarm_timeout,
            entity_selector=entity_selector,
            properties={
                "dt.event.correlation_tag": f"intersight-unreachable-{host}",
                "Alarm Name":               "IntersightUnreachable",
                "Severity":                 "Critical",
                "Intersight Host":          host,
                "Description":              f"Intersight host {host} is unreachable",
                "Error":                    str(error)[:200],
            }
        )
        self.logger.info(f"Sent unreachable event for {host}")

    def _refresh_cached_alarms(self, host: str, cached: dict,
                                alarm_timeout: int, entity_selector: str = None):
        """Refresh existing DT problems during outage using same title + correlation tag."""
        for moid, title in cached.items():
            self.report_dt_event(
                event_type=DtEventType.CUSTOM_ALERT,
                title=title,
                timeout=alarm_timeout,
                entity_selector=entity_selector,
                properties={
                    "dt.event.correlation_tag": f"intersight-{moid}",
                    "Intersight Host":          host,
                    "Intersight MOID":          moid,
                    "Status":                   "Refreshing - Intersight temporarily unavailable",
                }
            )
        self.logger.info(f"Refreshed {len(cached)} cached alarms for {host} during outage")

    def _poll_endpoint(self, endpoint: dict):
        alarm_timeout      = int(endpoint.get("alarm_timeout", 10))
        enabled_severities = get_enabled_severities(endpoint)
        severity_filter    = build_severity_filter(endpoint)

        base_url      = endpoint["url"].rstrip("/")
        client_id     = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy         = endpoint.get("proxy", "") or ""
        host          = base_url.replace("https://", "").replace("http://", "")

        try:
            token  = get_token(base_url, client_id, client_secret, proxy)
            alarms = get_active_alarms(base_url, token, proxy, severity_filter)

            self.logger.info(f"Polled {host}: {len(alarms)} active alarms")

            # Heartbeat metric
            self.report_metric(
                "intersight.heartbeat", 1,
                dimensions={"intersight_host": host}
            )

            # Entity selector
            entity_selector = self._get_entity_selector(host)

            # Build {moid: title} cache
            alarm_cache = {}
            for alarm in alarms:
                moid = alarm.get("Moid", "")
                if moid and alarm.get("Severity") in enabled_severities:
                    alarm_cache[moid] = self._build_event_title(alarm)

            # Update memory cache
            with _last_known_alarms_lock:
                _last_known_alarms[host] = alarm_cache

            # Save to file asynchronously
            threading.Thread(
                target=save_alarms_to_file,
                args=(host, alarm_cache),
                daemon=True
            ).start()

            # Send events for active alarms
            for alarm in alarms:
                if alarm.get("Severity") in enabled_severities:
                    self._send_alarm_event(
                        alarm, base_url, alarm_timeout, entity_selector
                    )

            self.logger.info(f"Finished processing {len(alarms)} alarms for {host}")

        except Exception as e:
            self.logger.exception(
                f"Intersight {host} unavailable - refreshing cached alarms"
            )

            entity_selector = self._get_entity_selector(host)

            # Send unreachable problem
            self._send_unreachable_event(host, str(e), alarm_timeout, entity_selector)

            # Refresh cached alarms
            with _last_known_alarms_lock:
                cached = dict(_last_known_alarms.get(host, {}))

            if cached:
                self.logger.info(f"Refreshing {len(cached)} cached alarms for {host}")
                self._refresh_cached_alarms(host, cached, alarm_timeout, entity_selector)
            else:
                self.logger.warning(f"No cached alarms for {host} - nothing to refresh")

    def fastcheck(self) -> Status:
        self.logger.info("fastcheck called")
        config  = self.get_activation_config()
        errors  = []
        for endpoint in config.get("endpoints", []):
            base_url      = endpoint["url"].rstrip("/")
            client_id     = endpoint["client_id"]
            client_secret = endpoint["client_secret"]
            proxy         = endpoint.get("proxy", "") or ""
            try:
                get_token(base_url, client_id, client_secret, proxy)
                self.logger.info(f"Fastcheck OK for {base_url}")
            except Exception as e:
                self.logger.error(f"Fastcheck failed for {base_url}: {e}")
                errors.append(str(e))

        if errors:
            return Status(StatusValue.DEVICE_CONNECTION_ERROR, "; ".join(errors))
        return Status(StatusValue.OK)


def main():
    ExtensionImpl(name="cisco_intersight").run()


if __name__ == "__main__":
    main()
