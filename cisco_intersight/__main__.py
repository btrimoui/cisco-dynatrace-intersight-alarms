import os
import urllib.parse
import urllib.request
import urllib.error
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
# Caches OAuth bearer tokens per Intersight base_url. Tokens are reused until
# ~60s before expiry to avoid re-authenticating on every poll. Concurrency-safe.
_token_cache = {}
_token_lock  = threading.Lock()

# ─── ALARM CACHE (account_moid -> {alarm_moid: title}) ────────────────────────
# Last-known active alarms per account, used both to detect resolutions
# (current vs previous diff) and to refresh DT problems during outages.
_last_known_alarms      = {}
_last_known_alarms_lock = threading.Lock()

# ─── ENTITY CONFIRMED CACHE (account_moid set, in-memory only) ────────────────
# Tracks accounts where the topology entity has been "warmed up" by a heartbeat.
# Skip alarm reporting on the very first poll (entity not yet materialized).
_entity_confirmed      = set()
_entity_confirmed_lock = threading.Lock()

# ─── STORAGE ──────────────────────────────────────────────────────────────────
STORAGE_DIR = "/var/lib/dynatrace/remotepluginmodule/storage/cisco_intersight"

# ─── KNOWN-USELESS ACCOUNT NAMES ──────────────────────────────────────────────
# Values returned by Intersight Appliance /iam/Accounts that aren't useful as
# entity display names. Lowercased for matching.
_USELESS_ACCOUNT_NAMES = {"admin", "default", ""}

# ─── RESOLUTION TIMEOUT ───────────────────────────────────────────────────────
# When an alarm disappears from active list (cleared or acknowledged in
# Intersight), send one final refresh with this short timeout so Davis closes
# the problem quickly instead of waiting the full alarm_timeout.
RESOLUTION_TIMEOUT_MIN = 1   # Davis minimum is 1 minute


def get_token(base_url: str, client_id: str, client_secret: str, proxy: str = "") -> str:
    """OAuth2 client_credentials → access token. Cached until near expiry."""
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


def fetch_account_identity(base_url: str, token: str, proxy: str = "") -> dict:
    """Fetch account Moid + Name via /api/v1/iam/Accounts. One-shot.

    Returns: {"moid": str, "name": str}
    Raises:  on HTTP errors or empty response.
    """
    params = urllib.parse.urlencode({
        "$select": "Name,Moid",
        "$top":    "1",
    })
    url = f"{base_url}/api/v1/iam/Accounts?{params}"
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
        results = json.loads(resp.read()).get("Results", [])
        if not results:
            raise RuntimeError("Intersight returned no account in /iam/Accounts response")
        return {
            "moid": results[0].get("Moid", "") or "",
            "name": results[0].get("Name", "") or "",
        }


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


def safe_key(s: str) -> str:
    return s.replace(".", "_").replace(":", "_").replace("/", "_")


def save_alarms_to_file(account_moid: str, alarms: dict):
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_key(account_moid)}_alarms.json"
        with open(path, "w") as f:
            json.dump(alarms, f)
    except Exception:
        pass


def load_alarms_from_file(account_moid: str) -> dict:
    try:
        path = f"{STORAGE_DIR}/{safe_key(account_moid)}_alarms.json"
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

        for endpoint in config.get("endpoints", []):
            if not endpoint.get("enable_alarms", True):
                continue

            poll_minutes = int(endpoint.get("poll_interval", 5))
            base_url     = endpoint["url"].rstrip("/")

            # Fast bootstrap: first poll at 30s warms up the topology entity
            # (heartbeat only, events deferred). Second poll at 90s emits
            # alarm events once Dynatrace's topology pipeline has materialized
            # the entity. Brings time-to-first-event from ~5-10 min → ~90 sec.
            self.logger.info(
                f"Scheduling bootstrap polls for {base_url} at 30s and 90s"
            )
            threading.Timer(
                30,
                lambda ep=endpoint: self._poll_endpoint(ep)
            ).start()
            threading.Timer(
                90,
                lambda ep=endpoint: self._poll_endpoint(ep)
            ).start()

            # Steady-state recurring polling at the configured interval
            self.logger.info(
                f"Scheduling regular polls for {base_url} every {poll_minutes} minutes"
            )
            self.schedule(
                lambda ep=endpoint: self._poll_endpoint(ep),
                timedelta(minutes=poll_minutes)
            )

    def query(self):
        pass

    def _is_first_poll(self, account_moid: str) -> bool:
        """True only on the very first poll for this account in the current process.
        Used to skip event reporting before the topology entity exists."""
        with _entity_confirmed_lock:
            if account_moid in _entity_confirmed:
                return False
            _entity_confirmed.add(account_moid)
            return True

    def _resolve_identity(self, endpoint: dict) -> dict:
        """Resolve and cache (per endpoint dict) the Intersight account identity.

        Lifetime: one fetch per endpoint per process.

        Account name resolution rules:
        - SaaS (URL ends with .intersight.com): use Name from /iam/Accounts.
        - Appliance / non-SaaS: API typically returns 'admin' which is useless
          as a display name — fall back to the appliance host (FQDN).
        - Also fall back to host if the API name is in _USELESS_ACCOUNT_NAMES
          regardless of deployment type.

        Returns dict with 'moid' and 'name'. Raises on failure.
        """
        identity = endpoint.get("_account_identity")
        if identity:
            return identity

        base_url      = endpoint["url"].rstrip("/")
        client_id     = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy         = endpoint.get("proxy", "") or ""

        token        = get_token(base_url, client_id, client_secret, proxy)
        raw_identity = fetch_account_identity(base_url, token, proxy)

        if not raw_identity.get("moid"):
            raise RuntimeError("Intersight returned an account without a Moid")

        host         = base_url.replace("https://", "").replace("http://", "")
        raw_name     = raw_identity.get("name", "") or ""
        normalized   = raw_name.strip().lower()

        if normalized in _USELESS_ACCOUNT_NAMES:
            account_name = host
            fallback     = "host (api name is generic/useless)"
        else:
            account_name = raw_name
            fallback     = "api name"

        identity = {
            "moid":         raw_identity["moid"],
            "name":         account_name,
            "raw_api_name": raw_name,
            "name_source":  fallback,
        }

        endpoint["_account_identity"] = identity
        self.logger.info(
            f"Resolved Intersight account: name={account_name!r}, "
            f"moid={identity['moid']}, source={fallback}, "
            f"raw_api_name={raw_name!r}"
        )
        return identity

    def _build_event_title(self, alarm: dict, account_name: str) -> str:
        name        = alarm.get("Name", "Unknown")
        severity    = alarm.get("Severity", "Info")
        description = alarm.get("Description", "No details")
        if account_name:
            return f"[{severity}] [{account_name}] {name}: {description[:120]}"
        return f"[{severity}] {name}: {description[:120]}"

    def _send_alarm_event(self, alarm: dict, base_url: str,
                          alarm_timeout: int, entity_selector: str,
                          account_name: str, account_moid: str):
        moid        = alarm.get("Moid", "")
        name        = alarm.get("Name", "Unknown")
        severity    = alarm.get("Severity", "Info")
        description = alarm.get("Description", "No details")
        code        = alarm.get("Code", "N/A")
        affected_mo = alarm.get("AffectedMoDisplayName") or alarm.get("AffectedMoType") or "N/A"
        alarm_host  = extract_hostname(base_url, alarm)
        title       = self._build_event_title(alarm, account_name)

        properties = {
            "dt.event.correlation_tag": f"intersight-{account_moid}-{moid}",
            "Alarm Name":               name,
            "Severity":                 severity,
            "Fault Code":               code,
            "Description":              description,
            "Affected Object":          affected_mo,
            "Intersight Host":          alarm_host,
            "Intersight MOID":          moid,
            "Intersight Account":       account_name,
            "Intersight Account MOID":  account_moid,
        }

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=title,
            timeout=alarm_timeout,
            entity_selector=entity_selector,
            properties=properties,
        )
        self.logger.info(f"Event sent: {name} severity={severity} moid={moid}")

    def _send_resolution_event(self, moid: str, previous_title: str,
                               entity_selector: str,
                               account_name: str, account_moid: str):
        """Send a final refresh for an alarm that is no longer active in
        Intersight (cleared or acknowledged). Same correlation_tag as original,
        but with a short timeout so Davis closes the problem quickly.
        """
        properties = {
            "dt.event.correlation_tag": f"intersight-{account_moid}-{moid}",
            "Alarm Name":               "AlarmResolved",
            "Severity":                 "Info",
            "Status":                   "Resolved (cleared or acknowledged in Intersight)",
            "Intersight Account":       account_name,
            "Intersight Account MOID":  account_moid,
            "Intersight MOID":          moid,
        }
        title = f"[Resolved] {previous_title}"

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=title,
            timeout=RESOLUTION_TIMEOUT_MIN,
            entity_selector=entity_selector,
            properties=properties,
        )
        self.logger.info(
            f"Sent resolution event for moid={moid} "
            f"(account={account_name}) — DT problem will close in "
            f"~{RESOLUTION_TIMEOUT_MIN} min"
        )

    def _send_unreachable_event(self, base_url: str, error: str,
                                alarm_timeout: int, entity_selector: str,
                                account_name: str, account_moid: str):
        host  = base_url.replace("https://", "").replace("http://", "")
        title = f"[Critical] Intersight host unreachable: {account_name}"
        properties = {
            "dt.event.correlation_tag": f"intersight-unreachable-{account_moid}",
            "Alarm Name":               "IntersightUnreachable",
            "Severity":                 "Critical",
            "Intersight Host":          host,
            "Intersight Account":       account_name,
            "Intersight Account MOID":  account_moid,
            "Description":              f"Intersight account {account_name} ({host}) is unreachable",
            "Error":                    str(error)[:200],
        }

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=title,
            timeout=alarm_timeout,
            entity_selector=entity_selector,
            properties=properties,
        )
        self.logger.info(f"Sent unreachable event for account {account_name} ({account_moid})")

    def _refresh_cached_alarms(self, base_url: str, cached: dict,
                                alarm_timeout: int, entity_selector: str,
                                account_name: str, account_moid: str):
        """During Intersight outage, replay cached titles so DT problems stay open."""
        host = base_url.replace("https://", "").replace("http://", "")
        for moid, title in cached.items():
            properties = {
                "dt.event.correlation_tag": f"intersight-{account_moid}-{moid}",
                "Intersight Host":          host,
                "Intersight MOID":          moid,
                "Intersight Account":       account_name,
                "Intersight Account MOID":  account_moid,
                "Status":                   "Refreshing - Intersight temporarily unavailable",
            }
            self.report_dt_event(
                event_type=DtEventType.CUSTOM_ALERT,
                title=title,
                timeout=alarm_timeout,
                entity_selector=entity_selector,
                properties=properties,
            )
        self.logger.info(
            f"Refreshed {len(cached)} cached alarms for account {account_name} during outage"
        )

    def _poll_endpoint(self, endpoint: dict):
        alarm_timeout      = int(endpoint.get("alarm_timeout", 10))
        enabled_severities = get_enabled_severities(endpoint)
        severity_filter    = build_severity_filter(endpoint)

        base_url      = endpoint["url"].rstrip("/")
        client_id     = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy         = endpoint.get("proxy", "") or ""
        host          = base_url.replace("https://", "").replace("http://", "")

        # Resolve identity (1 extra HTTP call on the very first poll only)
        try:
            identity = self._resolve_identity(endpoint)
        except Exception as e:
            self.logger.exception(
                f"Cannot resolve Intersight account identity for {base_url} - "
                f"skipping poll. Error: {e}"
            )
            return

        account_moid = identity["moid"]
        account_name = identity["name"] or account_moid

        # Hydrate alarm cache from disk on first poll for this account
        first_poll = self._is_first_poll(account_moid)
        if first_poll:
            cached_from_disk = load_alarms_from_file(account_moid)
            if cached_from_disk:
                with _last_known_alarms_lock:
                    _last_known_alarms[account_moid] = cached_from_disk
                self.logger.info(
                    f"Loaded {len(cached_from_disk)} cached alarms for account {account_name}"
                )

        try:
            token  = get_token(base_url, client_id, client_secret, proxy)
            alarms = get_active_alarms(base_url, token, proxy, severity_filter)

            self.logger.info(
                f"Polled {host} (account={account_name}, moid={account_moid}): "
                f"{len(alarms)} active alarms"
            )

            # Always send heartbeat — drives topology entity creation
            self.report_metric(
                "intersight.heartbeat", 1,
                dimensions={
                    "host":         host,
                    "account_name": account_name,
                    "account_moid": account_moid,
                }
            )

            # Build current alarm cache: {moid: title} for severities we care about
            new_alarm_cache = {}
            for alarm in alarms:
                moid = alarm.get("Moid", "")
                if moid and alarm.get("Severity") in enabled_severities:
                    new_alarm_cache[moid] = self._build_event_title(alarm, account_name)

            # First poll: skip event reporting (entity not yet materialized).
            # Just cache for the next poll's diff and outage refresh.
            if first_poll:
                self.logger.info(
                    f"First poll for account {account_name} — heartbeat sent, "
                    f"topology entity will materialize on next pipeline run. "
                    f"Alarm events deferred to next poll. "
                    f"({len(alarms)} alarms detected, {len(new_alarm_cache)} matching severity filter)"
                )
                with _last_known_alarms_lock:
                    _last_known_alarms[account_moid] = new_alarm_cache
                threading.Thread(
                    target=save_alarms_to_file,
                    args=(account_moid, new_alarm_cache),
                    daemon=True
                ).start()
                return

            # Subsequent polls — entity exists, safe to send events
            entity_selector = (
                f'type(cisco:intersight_domain),'
                f'account_moid("{account_moid}")'
            )

            # Detect resolutions: alarms in previous cache but not in current.
            with _last_known_alarms_lock:
                previous_cache = dict(_last_known_alarms.get(account_moid, {}))

            previous_moids = set(previous_cache.keys())
            current_moids  = set(new_alarm_cache.keys())
            resolved_moids = previous_moids - current_moids

            if resolved_moids:
                self.logger.info(
                    f"Detected {len(resolved_moids)} resolved alarm(s) for account "
                    f"{account_name} (cleared or acknowledged in Intersight)"
                )
                for moid in resolved_moids:
                    previous_title = previous_cache.get(moid, "Unknown alarm")
                    self._send_resolution_event(
                        moid, previous_title, entity_selector,
                        account_name=account_name, account_moid=account_moid,
                    )

            # Update memory + disk cache to current state
            with _last_known_alarms_lock:
                _last_known_alarms[account_moid] = new_alarm_cache

            threading.Thread(
                target=save_alarms_to_file,
                args=(account_moid, new_alarm_cache),
                daemon=True
            ).start()

            # Send (or refresh) events for active alarms
            for alarm in alarms:
                if alarm.get("Severity") in enabled_severities:
                    self._send_alarm_event(
                        alarm, base_url, alarm_timeout, entity_selector,
                        account_name=account_name, account_moid=account_moid,
                    )

            self.logger.info(
                f"Finished processing {len(alarms)} alarms for account {account_name} "
                f"({len(resolved_moids)} resolved, {len(new_alarm_cache)} active)"
            )

        except Exception as e:
            self.logger.exception(
                f"Intersight {host} (account={account_name}) unavailable - "
                f"refreshing cached alarms"
            )

            # If the very first poll fails, we have no entity yet — skip the
            # unreachable event to avoid a tenant-level problem.
            if first_poll:
                self.logger.warning(
                    f"First poll for account {account_name} failed. "
                    f"Skipping unreachable event to avoid tenant-level problem. "
                    f"Will retry next interval."
                )
                return

            entity_selector = (
                f'type(cisco:intersight_domain),'
                f'account_moid("{account_moid}")'
            )

            self._send_unreachable_event(
                base_url, str(e), alarm_timeout, entity_selector,
                account_name=account_name, account_moid=account_moid,
            )

            with _last_known_alarms_lock:
                cached = dict(_last_known_alarms.get(account_moid, {}))

            if cached:
                self.logger.info(
                    f"Refreshing {len(cached)} cached alarms for account {account_name}"
                )
                self._refresh_cached_alarms(
                    base_url, cached, alarm_timeout, entity_selector,
                    account_name=account_name, account_moid=account_moid,
                )
            else:
                self.logger.warning(
                    f"No cached alarms for account {account_name} - nothing to refresh"
                )

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
                token    = get_token(base_url, client_id, client_secret, proxy)
                identity = fetch_account_identity(base_url, token, proxy)
                if not identity.get("moid"):
                    msg = (
                        f"{base_url}: Intersight account has no Moid. "
                        f"Verify the OAuth Read Only role grants access to /iam/Accounts."
                    )
                    self.logger.error(msg)
                    errors.append(msg)
                    continue
                self.logger.info(
                    f"Fastcheck OK for {base_url} "
                    f"(account_name={identity.get('name')!r}, moid={identity.get('moid')})"
                )
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    msg = (
                        f"{base_url}: Authentication failed (HTTP 401). "
                        f"Check Client ID and Client Secret."
                    )
                elif e.code == 403:
                    msg = (
                        f"{base_url}: Access denied (HTTP 403). "
                        f"Verify the OAuth Read Only role grants access to /iam/Accounts."
                    )
                else:
                    msg = f"{base_url}: HTTP error {e.code} from Intersight."
                self.logger.error(msg)
                errors.append(msg)
            except Exception as e:
                msg = f"{base_url}: {e}"
                self.logger.error(f"Fastcheck failed for {base_url}: {e}")
                errors.append(msg)

        if errors:
            return Status(StatusValue.DEVICE_CONNECTION_ERROR, "; ".join(errors))
        return Status(StatusValue.OK)


def main():
    ExtensionImpl(name="cisco_intersight").run()


if __name__ == "__main__":
    main()
