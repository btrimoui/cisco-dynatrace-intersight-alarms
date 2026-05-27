import os
import urllib.parse
import urllib.request
import urllib.error
import ssl
import json
import time
import threading
import hashlib
from datetime import timedelta, datetime, timezone
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

# ─── ADVISORY CACHE (account_moid -> {advisory_moid: rollup_dict}) ────────────
# Last-known active advisories per account. Same pattern as _last_known_alarms.
_last_known_advisories      = {}
_last_known_advisories_lock = threading.Lock()

# ─── ADVISORY DEFINITION CATALOG (account_moid -> {advisory_moid: definition}) ─
# Per-account catalog cache for advisory definitions (PSIRT + AdvisoryDefinitions).
# Built incrementally with ModTime watermarks.
_advisory_catalog      = {}
_advisory_catalog_lock = threading.Lock()

# ─── ADVISORY WATERMARKS (account_moid -> {endpoint_key: ModTime}) ────────────
_advisory_watermarks      = {}
_advisory_watermarks_lock = threading.Lock()

# ─── ENTITY CONFIRMED CACHE (account_moid set, in-memory only) ────────────────
# Tracks accounts where the topology entity has been "warmed up" by a heartbeat
# in the current process lifetime. Combined with on-disk cache existence to
# decide whether to defer event reporting (only for genuinely new accounts).
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

# ─── ADVISORY KEEPALIVE ───────────────────────────────────────────────────────
# Davis closes custom-alert problems after 6h of silence. Re-emit cached
# advisory events every 5h to keep them open without hitting the API.
ADVISORY_KEEPALIVE_HOURS = 5

# ─── ADVISORY ODATA PROJECTIONS ───────────────────────────────────────────────
# Drops massive Actions/ApiDataSources/Queries blobs (~95% payload reduction).
ADVISORY_SELECT = ",".join([
    "Moid", "Name", "AdvisoryId",
    "Severity", "BaseScore", "TemporalScore", "EnvironmentalScore",
    "CveIds", "DatePublished", "DateUpdated", "ModTime",
    "ExternalUrl", "Description", "Recommendation", "Workaround",
    "Status", "State", "Version",
])

INSTANCE_SELECT = ",".join([
    "Moid", "Advisory", "AffectedObject",
    "Acknowledged", "AcknowledgedTime", "LastVerifiedTime", "ModTime",
])

# ─── HTTP RETRY / TLS / VALIDATION HELPERS (v1.2.0) ───────────────────────────

# Identity TTL: how long a resolved (account_moid, account_name) is cached
# before re-querying /iam/Accounts. Renames in Intersight are rare; 24h is
# a good balance between freshness and API call savings.
IDENTITY_TTL_SECONDS = 24 * 60 * 60

# Retry config for transient HTTP errors (URLError, 5xx).
HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_BACKOFF  = [2, 5, 10]   # seconds between attempts

# CA bundle discovery for the Dynatrace-bundled Python runtime.
# The bundled Python's compile-time CA path points to Jenkins build server
# directories that don't exist on customer hosts, so create_default_context()
# loads zero CAs and all HTTPS verification fails. We discover the OS's CA
# bundle and load it explicitly.
_SYSTEM_CA_CANDIDATES = [
    "/etc/pki/tls/certs/ca-bundle.crt",            # RHEL / CentOS / Fedora
    "/etc/ssl/certs/ca-certificates.crt",          # Debian / Ubuntu
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL alt path
    "/etc/ssl/cert.pem",                           # Alpine / BSD / macOS
]


def _build_verified_ctx() -> ssl.SSLContext:
    """Build an SSL context with a CA bundle the bundled Python can find.

    Falls back to create_default_context() (which is broken in the bundled
    runtime) only if no system CA bundle is found — at which point users
    can disable verify_tls per endpoint as a workaround.
    """
    for ca_path in _SYSTEM_CA_CANDIDATES:
        try:
            if os.path.isfile(ca_path):
                return ssl.create_default_context(cafile=ca_path)
        except (OSError, ssl.SSLError):
            continue
    return ssl.create_default_context()


_VERIFIED_CTX = _build_verified_ctx()


def _normalize_url(endpoint: dict) -> str:
    """Strip trailing slash from endpoint URL. Centralizes the v1.0.5 logic
    so we don't repeat it in 5+ places."""
    return (endpoint.get("url") or "").rstrip("/")


def _ssl_context_for(endpoint: dict) -> ssl.SSLContext:
    """Return a verifying or non-verifying SSL context based on endpoint
    settings. v1.2.0 makes this user-configurable; default is to VERIFY.
    """
    if endpoint.get("verify_tls", True):
        return _VERIFIED_CTX
    return NO_VERIFY_CTX


def _account_cache_key(base_url: str, account_moid: str) -> str:
    """Bundle base_url + account_moid for cache lookups so two endpoints
    with the same moid (different Intersight regions/appliances) don't
    collide. Hashed prefix keeps disk filenames manageable.
    """
    h = hashlib.sha256(base_url.encode()).hexdigest()[:8]
    return f"{h}_{account_moid}"


def _http_request(url: str, *, method: str = "GET", data: bytes = None,
                  headers: dict = None, proxy: str = "",
                  ssl_ctx: ssl.SSLContext = None,
                  timeout: int = 15) -> bytes:
    """Single HTTP request with retry on URLError and 5xx HTTP errors.

    Returns response body bytes. Raises after final attempt fails.
    """
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
    last_err = None
    for attempt in range(HTTP_RETRY_ATTEMPTS):
        try:
            req = urllib.request.Request(
                url, data=data,
                headers=headers or {},
                method=method,
            )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"https": proxy} if proxy else {}),
                urllib.request.HTTPSHandler(context=ssl_ctx),
            )
            with opener.open(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            # 4xx errors are not transient — fail fast (auth, bad request)
            if 400 <= e.code < 500:
                raise
            last_err = e
        except (urllib.error.URLError, OSError) as e:
            last_err = e

        if attempt < HTTP_RETRY_ATTEMPTS - 1:
            time.sleep(HTTP_RETRY_BACKOFF[attempt])
    # All retries exhausted
    raise last_err


def _parse_intersight_results(body: bytes, url: str) -> tuple:
    """Parse Intersight JSON response, return (results, next_link).

    Validates response shape; raises RuntimeError on malformed payloads.
    """
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Intersight returned non-JSON from {url}: {e}")

    # Some endpoints return error wrapped in a different shape
    if isinstance(payload, dict) and "Error" in payload and "Results" not in payload:
        raise RuntimeError(f"Intersight error response from {url}: {payload['Error']}")

    if not isinstance(payload, dict):
        raise RuntimeError(f"Intersight returned unexpected JSON shape from {url}")

    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise RuntimeError(f"Intersight 'Results' is not a list in response from {url}")

    next_link = payload.get("@odata.nextLink", "")
    return results, next_link


def _paginated_fetch(base_url: str, path_with_query: str, headers: dict,
                     proxy: str, ssl_ctx: ssl.SSLContext,
                     timeout: int = 30) -> list:
    """Fetch all pages of a list-returning Intersight endpoint."""
    results = []
    url = f"{base_url}{path_with_query}"
    page = 0
    while url and page < 50:  # safety cap: 50 pages × 1000 = 50k items
        body = _http_request(url, headers=headers, proxy=proxy,
                             ssl_ctx=ssl_ctx, timeout=timeout)
        page_results, next_link = _parse_intersight_results(body, url)
        results.extend(page_results)
        if next_link:
            url = next_link if next_link.startswith("http") else f"{base_url}{next_link}"
        else:
            url = None
        page += 1
    return results


def get_token(base_url: str, client_id: str, client_secret: str,
              proxy: str = "", ssl_ctx: ssl.SSLContext = None) -> str:
    """OAuth2 client_credentials → access token. Cached until near expiry.

    v1.2.0 changes:
      - cache key includes client_id (already in v1.1.8) and base_url
      - retry on transient errors via _http_request
      - sanity-check expires_in (reject obviously bogus values)
    """
    import base64
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
    cache_key = f"{base_url}|{client_id}"
    with _token_lock:
        now    = time.time()
        cached = _token_cache.get(cache_key)
        if cached and now < cached["expires_at"] - 60:
            return cached["token"]

        url     = f"{base_url}/iam/token"
        payload = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
        creds   = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

        body = _http_request(
            url,
            method="POST",
            data=payload,
            headers={
                "Content-Type":  "application/x-www-form-urlencoded",
                "Authorization": f"Basic {creds}",
            },
            proxy=proxy,
            ssl_ctx=ssl_ctx,
            timeout=15,
        )
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"OAuth token response is not valid JSON: {e}")

        token = data.get("access_token")
        if not token:
            raise RuntimeError(f"OAuth response missing access_token: keys={list(data.keys())}")

        expires_in = int(data.get("expires_in", 3600))
        # Sanity: reject negative, zero, or absurdly large values
        if expires_in < 60 or expires_in > 24 * 3600:
            expires_in = 3600  # fallback to 1h

        _token_cache[cache_key] = {
            "token":      token,
            "expires_at": now + expires_in,
        }
        return token


def fetch_account_identity(base_url: str, token: str, proxy: str = "",
                            ssl_ctx: ssl.SSLContext = None) -> dict:
    """Fetch account Moid + Name via /api/v1/iam/Accounts. One-shot."""
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
    params = urllib.parse.urlencode({
        "$select": "Name,Moid",
        "$top":    "1",
    })
    url = f"{base_url}/api/v1/iam/Accounts?{params}"
    body = _http_request(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        proxy=proxy, ssl_ctx=ssl_ctx, timeout=15,
    )
    results, _ = _parse_intersight_results(body, url)
    if not results:
        raise RuntimeError("Intersight returned no account in /iam/Accounts response")
    return {
        "moid": results[0].get("Moid", "") or "",
        "name": results[0].get("Name", "") or "",
    }


def get_active_alarms(base_url: str, token: str,
                      proxy: str = "", severity_filter: str = "",
                      ssl_ctx: ssl.SSLContext = None) -> list:
    """v1.2.0: paginated, retry-aware, configurable TLS."""
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
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
    return _paginated_fetch(
        base_url, f"/api/v1/cond/Alarms?{params}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        proxy=proxy, ssl_ctx=ssl_ctx, timeout=15,
    )


def get_advisory_definitions(base_url: str, token: str, api_path: str,
                             proxy: str = "", since_modtime: str = "",
                             ssl_ctx: ssl.SSLContext = None) -> list:
    """v1.2.0: paginated, retry-aware, configurable TLS."""
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
    query = {
        "$select":  ADVISORY_SELECT,
        "$orderby": "ModTime asc",
        "$top":     "1000",
    }
    if since_modtime:
        query["$filter"] = f"ModTime gt {since_modtime}"

    params = urllib.parse.urlencode(query)
    return _paginated_fetch(
        base_url, f"{api_path}?{params}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        proxy=proxy, ssl_ctx=ssl_ctx, timeout=30,
    )


def get_advisory_instances(base_url: str, token: str, proxy: str = "",
                           ssl_ctx: ssl.SSLContext = None) -> list:
    """v1.2.0: paginated, retry-aware, configurable TLS.
    Acknowledged filter is still client-side (Intersight OData boolean is unreliable).
    """
    if ssl_ctx is None:
        ssl_ctx = NO_VERIFY_CTX
    params = urllib.parse.urlencode({
        "$select": INSTANCE_SELECT,
        "$top":    "1000",
    })
    all_instances = _paginated_fetch(
        base_url, f"/api/v1/tam/AdvisoryInstances?{params}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        proxy=proxy, ssl_ctx=ssl_ctx, timeout=30,
    )
    return [
        inst for inst in all_instances
        if not inst.get("Acknowledged", False)
    ]


def infer_alert_type(definition: dict) -> str:
    """Determine PSIRT / FN / EOL from advisory metadata."""
    obj_type = (definition.get("ObjectType") or "").lower()
    if "security" in obj_type:
        return "psirt"
    advisory_id = (definition.get("AdvisoryId") or "").lower()
    if advisory_id.startswith("cisco-sa-"):
        return "psirt"
    if advisory_id.startswith("cisco-fn-"):
        return "fieldNotice"
    if "eol" in advisory_id or "end-of-life" in advisory_id:
        return "endOfLife"
    return "fieldNotice"


def rollup_advisories(instances: list, definitions: dict, type_filters: dict) -> dict:
    """Group instances by Advisory.Moid, enriching with definition data.

    Returns: {advisory_moid: {advisory metadata + alert_type + affected_count + affected_moids}}
    """
    rollup = {}
    for inst in instances:
        adv_ref = inst.get("Advisory") or {}
        adv_moid = adv_ref.get("Moid")
        if not adv_moid:
            continue
        definition = definitions.get(adv_moid)
        if not definition:
            continue  # Definition not in catalog yet; will be picked up next cycle
        alert_type = infer_alert_type(definition)
        if not type_filters.get(alert_type, True):
            continue
        if adv_moid not in rollup:
            entry = dict(definition)
            entry["alert_type"] = alert_type
            entry["affected_count"] = 0
            entry["affected_moids"] = []
            rollup[adv_moid] = entry
        rollup[adv_moid]["affected_count"] += 1
        affected_obj = inst.get("AffectedObject") or {}
        if affected_obj.get("Moid"):
            rollup[adv_moid]["affected_moids"].append(affected_obj["Moid"])
    return rollup


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


def get_advisory_type_filters(endpoint: dict) -> dict:
    """Map activation schema toggles to alert_type strings used in rollup."""
    return {
        "psirt":       endpoint.get("advisories_include_psirt", True),
        "fieldNotice": endpoint.get("advisories_include_fn", True),
        "endOfLife":   endpoint.get("advisories_include_eol", True),
    }


def safe_key(s: str) -> str:
    return s.replace(".", "_").replace(":", "_").replace("/", "_")


def save_alarms_to_file(cache_key: str, alarms: dict):
    """Persist alarm cache. cache_key includes base_url hash + account_moid
    to prevent collisions across endpoints with the same account_moid."""
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_alarms.json"
        with open(path, "w") as f:
            json.dump(alarms, f)
    except Exception:
        pass


def load_alarms_from_file(cache_key: str) -> dict:
    try:
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_alarms.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_advisories_to_file(cache_key: str, advisories: dict):
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_advisories.json"
        with open(path, "w") as f:
            json.dump(advisories, f)
    except Exception:
        pass


def load_advisories_from_file(cache_key: str) -> dict:
    try:
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_advisories.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_advisory_catalog_to_file(cache_key: str, catalog_key: str, catalog: dict):
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_catalog_{catalog_key}.json"
        with open(path, "w") as f:
            json.dump(catalog, f)
    except Exception:
        pass


def load_advisory_catalog_from_file(cache_key: str, catalog_key: str) -> dict:
    try:
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_catalog_{catalog_key}.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_watermarks_to_file(cache_key: str, watermarks: dict):
    try:
        os.makedirs(STORAGE_DIR, exist_ok=True)
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_watermarks.json"
        with open(path, "w") as f:
            json.dump(watermarks, f)
    except Exception:
        pass


def load_watermarks_from_file(cache_key: str) -> dict:
    try:
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_watermarks.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


class ExtensionImpl(Extension):

    def initialize(self):
        self.logger.info("initialize called (v1.2.3)")
        config = self.get_activation_config()

        # Track which endpoints have schedules registered in this process,
        # so repeated initialize() calls (config reloads, endpoint additions)
        # don't stack up duplicate polls.
        if not hasattr(self, "_scheduled_endpoints"):
            self._scheduled_endpoints = set()

        # Track the live set of (base_url, client_id) keys from the *current*
        # config. Schedule callbacks check this before running, so endpoints
        # removed from config naturally stop polling without leaking schedules.
        self._live_endpoints = set()
        for endpoint in config.get("endpoints", []):
            base_url  = _normalize_url(endpoint)
            client_id = endpoint.get("client_id", "")
            self._live_endpoints.add(f"{base_url}|{client_id}")

        for endpoint in config.get("endpoints", []):
            base_url     = _normalize_url(endpoint)
            client_id    = endpoint.get("client_id", "")
            poll_minutes = int(endpoint.get("poll_interval", 5))

            schedule_key = f"{base_url}|{client_id}"
            if schedule_key in self._scheduled_endpoints:
                self.logger.info(
                    f"Endpoint {base_url} (client_id prefix={client_id[:8]}) "
                    f"already scheduled, skipping duplicate registration"
                )
                continue
            self._scheduled_endpoints.add(schedule_key)

            # ── Alarm polling ──────────────────────────────────────────────
            if endpoint.get("enable_alarms", True):
                self.logger.info(
                    f"Scheduling bootstrap alarm polls for {base_url} at 30s and 90s"
                )
                threading.Timer(
                    30,
                    lambda ep=endpoint: self._guarded_poll_endpoint(ep)
                ).start()
                threading.Timer(
                    90,
                    lambda ep=endpoint: self._guarded_poll_endpoint(ep)
                ).start()

                self.logger.info(
                    f"Scheduling regular alarm polls for {base_url} every {poll_minutes} minutes"
                )
                self.schedule(
                    lambda ep=endpoint: self._guarded_poll_endpoint(ep),
                    timedelta(minutes=poll_minutes)
                )

            # ── Advisory polling (opt-in) ─────────────────────────────
            if endpoint.get("advisories_enabled", False):
                advisory_hours = int(endpoint.get("advisories_poll_hours", 24) or 24)
                if advisory_hours < 1:
                    self.logger.warning(
                        f"advisories_poll_hours={advisory_hours} too low; clamping to 1"
                    )
                    advisory_hours = 1

                self.logger.info(
                    f"Scheduling bootstrap advisory poll for {base_url} at 120s"
                )
                threading.Timer(
                    120,
                    lambda ep=endpoint: self._guarded_poll_advisories(ep)
                ).start()

                self.logger.info(
                    f"Scheduling regular advisory polls for {base_url} every {advisory_hours} hours"
                )
                self.schedule(
                    lambda ep=endpoint: self._guarded_poll_advisories(ep),
                    timedelta(hours=advisory_hours)
                )

                if advisory_hours > ADVISORY_KEEPALIVE_HOURS:
                    self.logger.info(
                        f"Scheduling advisory keepalive for {base_url} every "
                        f"{ADVISORY_KEEPALIVE_HOURS} hours"
                    )
                    self.schedule(
                        lambda ep=endpoint: self._guarded_refresh_advisories(ep),
                        timedelta(hours=ADVISORY_KEEPALIVE_HOURS)
                    )


    def query(self):
        pass

    def _is_first_poll(self, account_moid: str) -> bool:
        """True only on the very first poll for this account in the current process."""
        with _entity_confirmed_lock:
            if account_moid in _entity_confirmed:
                return False
            _entity_confirmed.add(account_moid)
            return True

    def _is_account_known(self, cache_key: str) -> bool:
        """True if this account has been successfully polled for alarms in
        a prior process lifetime on this AG. The presence of the alarm
        cache file is our 'entity has been confirmed' signal; this avoids
        deferring events on every process restart, which would otherwise
        trigger Davis problem timeouts and a close/reopen storm at scale.

        Note: cache files are not auto-cleaned when an account is removed
        from config. They persist as orphans (~few KB each) until manually
        cleaned. If a removed account is later re-added, the first poll
        may emit spurious 'resolved' events from the stale cache. This is
        an acceptable trade-off vs. the ServiceNow ticket storm risk on
        the far more common config-change path.
        """
        path = f"{STORAGE_DIR}/{safe_key(cache_key)}_alarms.json"
        return os.path.exists(path)

    def _is_endpoint_live(self, endpoint: dict) -> bool:
        """v1.2.0 (B1): poll callbacks check this so removed endpoints stop polling.
        Reads _live_endpoints which is rebuilt from config on each initialize()."""
        base_url  = _normalize_url(endpoint)
        client_id = endpoint.get("client_id", "")
        live = getattr(self, "_live_endpoints", set())
        return f"{base_url}|{client_id}" in live

    def _guarded_poll_endpoint(self, endpoint: dict):
        if not self._is_endpoint_live(endpoint):
            self.logger.debug(
                f"Skipping alarm poll for {_normalize_url(endpoint)} — "
                f"endpoint removed from config"
            )
            return
        return self._poll_endpoint(endpoint)

    def _guarded_poll_advisories(self, endpoint: dict):
        if not self._is_endpoint_live(endpoint):
            self.logger.debug(
                f"Skipping advisory poll for {_normalize_url(endpoint)} — "
                f"endpoint removed from config"
            )
            return
        return self._poll_advisories_endpoint(endpoint)

    def _guarded_refresh_advisories(self, endpoint: dict):
        if not self._is_endpoint_live(endpoint):
            self.logger.debug(
                f"Skipping advisory keepalive for {_normalize_url(endpoint)} — "
                f"endpoint removed from config"
            )
            return
        return self._refresh_advisories_from_cache(endpoint)

    def _resolve_identity(self, endpoint: dict) -> dict:
        """Resolve and cache the Intersight account identity per (base_url, client_id).

        v1.2.0:
          - Cache lives on the ExtensionImpl instance, NOT on the activation_config dict.
          - 24h TTL allows account renames to be picked up.
          - SSL context derived from endpoint.verify_tls.
        """
        if not hasattr(self, "_identity_cache"):
            self._identity_cache = {}

        base_url     = _normalize_url(endpoint)
        client_id    = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy        = endpoint.get("proxy", "") or ""
        ssl_ctx      = _ssl_context_for(endpoint)

        ck = f"{base_url}|{client_id}"
        cached = self._identity_cache.get(ck)
        if cached and time.time() < cached["expires_at"]:
            return cached["identity"]

        token        = get_token(base_url, client_id, client_secret, proxy, ssl_ctx)
        raw_identity = fetch_account_identity(base_url, token, proxy, ssl_ctx)

        if not raw_identity.get("moid"):
            raise RuntimeError("Intersight returned an account without a Moid")

        host       = base_url.replace("https://", "").replace("http://", "")
        raw_name   = raw_identity.get("name", "") or ""
        normalized = raw_name.strip().lower()

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

        self._identity_cache[ck] = {
            "identity":   identity,
            "expires_at": time.time() + IDENTITY_TTL_SECONDS,
        }

        self.logger.info(
            f"Resolved Intersight account: name={account_name!r}, "
            f"moid={identity['moid']}, source={fallback}, "
            f"raw_api_name={raw_name!r} (ttl={IDENTITY_TTL_SECONDS}s)"
        )
        return identity

    def _build_event_title(self, alarm: dict, account_name: str = "") -> str:
        """Build the event title shown in Davis problem cards.

        v1.0.5: Intersight Account is intentionally NOT included in the title
        since it's already visible via the affected entity name and the
        'Intersight Account' event property — adding it to the title was just
        visual noise. The account_name parameter is kept on the signature for
        backward compatibility with existing callers.
        """
        name        = alarm.get("Name", "Unknown")
        severity    = alarm.get("Severity", "Info")
        description = alarm.get("Description", "No details")
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
        self.logger.debug(f"Event sent: {name} severity={severity} moid={moid}")

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
        self.logger.debug(
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
        # Davis closes alarm problems via explicit _send_resolution_event when
        # alarms clear in Intersight. The timeout below is a safety net for cases
        # where the extension goes silent (AG restart, host maintenance, network
        # outage). 6h (Davis maximum) avoids mass close/reopen cycles on transient
        # AG unavailability while still bounding stale-problem lifetime if the
        # extension is disabled or uninstalled.
        alarm_timeout      = 360
        enabled_severities = get_enabled_severities(endpoint)
        severity_filter    = build_severity_filter(endpoint)

        base_url      = _normalize_url(endpoint)
        client_id     = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy         = endpoint.get("proxy", "") or ""
        host          = base_url.replace("https://", "").replace("http://", "")
        ssl_ctx       = _ssl_context_for(endpoint)

        # Resolve identity (cached per (base_url, client_id) with 24h TTL)
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
        cache_key    = _account_cache_key(base_url, account_moid)

        # v1.2.3: distinguish "first poll in this process" from "brand-new account"
        first_poll_in_process = self._is_first_poll(account_moid)
        account_is_brand_new  = first_poll_in_process and not self._is_account_known(cache_key)

        # Hydrate alarm cache from disk on first poll for this account in this process
        if first_poll_in_process:
            cached_from_disk = load_alarms_from_file(cache_key)
            if cached_from_disk:
                with _last_known_alarms_lock:
                    _last_known_alarms[cache_key] = cached_from_disk
                self.logger.info(
                    f"Loaded {len(cached_from_disk)} cached alarms for account {account_name}"
                )

        try:
            token  = get_token(base_url, client_id, client_secret, proxy, ssl_ctx)
            alarms = get_active_alarms(base_url, token, proxy, severity_filter, ssl_ctx)

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

            # v1.2.3: only defer events on truly brand-new accounts. For known
            # accounts (where the topology entity already exists from prior
            # process lifetime), send events immediately to avoid Davis problem
            # timeout → close → reopen storm on every config change.
            if account_is_brand_new:
                self.logger.info(
                    f"Brand-new account {account_name} — heartbeat sent, "
                    f"topology entity will materialize on next pipeline run. "
                    f"Alarm events deferred to next poll. "
                    f"({len(alarms)} alarms detected, {len(new_alarm_cache)} matching severity filter)"
                )
                with _last_known_alarms_lock:
                    _last_known_alarms[cache_key] = new_alarm_cache
                threading.Thread(
                    target=save_alarms_to_file,
                    args=(cache_key, new_alarm_cache),
                    daemon=True
                ).start()
                return

            # Subsequent polls (or first-poll-of-known-account) — entity exists, safe to send events
            entity_selector = (
                f'type(cisco:intersight_domain),'
                f'account_moid("{account_moid}")'
            )

            # Detect resolutions: alarms in previous cache but not in current.
            with _last_known_alarms_lock:
                previous_cache = dict(_last_known_alarms.get(cache_key, {}))

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
                _last_known_alarms[cache_key] = new_alarm_cache

            threading.Thread(
                target=save_alarms_to_file,
                args=(cache_key, new_alarm_cache),
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

            # v1.2.3: only skip the unreachable event for genuinely brand-new
            # accounts (entity not yet materialized). Known accounts get
            # immediate notification of the failure.
            if account_is_brand_new:
                self.logger.warning(
                    f"First poll for brand-new account {account_name} failed. "
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
                cached = dict(_last_known_alarms.get(cache_key, {}))

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

    # ─── ADVISORY POLLING (v1.1.1) ─────────────────────────────────────────────

    def _normalize_advisory_severity(self, advisory: dict) -> str:
        """Return a usable severity string. Cisco's API returns 'na' for
        EOL/FN advisories — replace it with something readable."""
        raw_sev = (advisory.get("Severity") or {}).get("Level", "") or ""
        normalized = raw_sev.strip().lower()
        if normalized in ("", "na", "none", "informational"):
            alert_type = advisory.get("alert_type", "")
            return {
                "endOfLife":   "End of Life",
                "fieldNotice": "Field Notice",
                "psirt":       "Informational",
            }.get(alert_type, "Informational")
        return raw_sev.capitalize()

    def _build_advisory_description(self, advisory: dict) -> str:
        parts = []
        desc = (advisory.get("Description") or "").strip()
        if desc:
            parts.append(desc[:800])
        rec = (advisory.get("Recommendation") or "").strip()
        if rec:
            parts.append(f"\n\nRecommendation: {rec[:800]}")
        wa = (advisory.get("Workaround") or "").strip()
        if wa:
            parts.append(f"\n\nWorkaround: {wa[:400]}")
        return "".join(parts) or advisory.get("Name", "Cisco Advisory")

    def _build_advisory_title(self, advisory: dict) -> str:
        """Build advisory event title.

        Davis only recognizes severity prefixes that map to its severity model
        (Critical, High, Medium, Low, Informational). Cisco's TAM API returns
        'na' for EOL/FN advisories — we map those to 'Informational' so Davis
        ingests them rather than silently dropping the events.

        The Advisory Type property carries the actual classification (PSIRT /
        EOL / Field Notice) for filtering and dashboards.
        """
        raw_sev = (advisory.get("Severity") or {}).get("Level", "") or ""
        normalized = raw_sev.strip().lower()

        if normalized in ("", "na", "none", "informational"):
            sev_label = "Informational"
        elif normalized == "critical":
            sev_label = "Critical"
        elif normalized == "high":
            sev_label = "High"
        elif normalized == "medium":
            sev_label = "Medium"
        elif normalized == "low":
            sev_label = "Low"
        else:
            sev_label = "Informational"

        # Annotate the type after the severity so EOL/FN are still visually
        # distinguishable from PSIRT in the Davis problem list.
        type_tag = {
            "endOfLife":   "EOL",
            "fieldNotice": "FN",
            "psirt":       "PSIRT",
        }.get(advisory.get("alert_type", ""), "")

        name = advisory.get("Name") or advisory.get("AdvisoryId", "Cisco Advisory")
        prefix = f"[{sev_label}]"
        if type_tag:
            prefix += f"[{type_tag}]"
        return f"{prefix} Cisco Advisory: {name[:160]}"

    @staticmethod
    def _clean(value, max_len: int = 4000) -> str:
        """Make a value safe for Dynatrace event properties.
        Strips markdown links, control chars, and caps length."""
        import re
        if value is None:
            return ""
        if not isinstance(value, str):
            value = str(value)
        # Convert markdown links [label](url) → "label (url)"
        value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
        # Strip control chars except newline and tab
        value = "".join(
            ch for ch in value
            if ch in ("\n", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
        )
        return value[:max_len]

    def _send_advisory_event(self, advisory: dict, entity_selector: str,
                             account_name: str, account_moid: str,
                             timeout_minutes: int = 360):
        advisory_id = advisory.get("AdvisoryId") or advisory.get("Moid", "unknown")
        cve_list = advisory.get("CveIds") or []

        # Default placeholder strings — Davis sometimes drops events on empty fields
        properties = {
            "dt.event.correlation_tag": f"intersight-advisory-{account_moid}-{advisory_id}",
            "Advisory ID":              self._clean(advisory_id),
            "Advisory Type":            self._clean(advisory.get("alert_type", "unknown")),
            "Advisory Name":            self._clean(advisory.get("Name", "")),
            "Severity":                 self._clean(self._normalize_advisory_severity(advisory)),
            "CVSS Base Score":          self._clean(advisory.get("BaseScore", "")) or "N/A",
            "CVSS Temporal Score":      self._clean(advisory.get("TemporalScore", "")) or "N/A",
            "CVE IDs":                  self._clean(", ".join(cve_list)) or "N/A",
            "CVE Count":                self._clean(len(cve_list)),
            "External URL":             self._clean(advisory.get("ExternalUrl", "")) or "N/A",
            "Affected Count":           self._clean(advisory.get("affected_count", 0)),
            "Date Published":           self._clean(advisory.get("DatePublished", "")) or "N/A",
            "Date Updated":             self._clean(advisory.get("DateUpdated", "")) or "N/A",
            "Status":                   self._clean(advisory.get("Status", "")) or "N/A",
            "Version":                  self._clean(advisory.get("Version", "")) or "N/A",
            "Description":              self._clean(self._build_advisory_description(advisory)),
            "Intersight Account":       self._clean(account_name),
            "Intersight Account MOID":  self._clean(account_moid),
        }

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=self._build_advisory_title(advisory),
            timeout=timeout_minutes,
            entity_selector=entity_selector,
            properties=properties,
        )
        self.logger.debug(
            f"Advisory event sent: {advisory_id} "
            f"type={advisory.get('alert_type')} affected={advisory.get('affected_count', 0)}"
        )


    def _send_advisory_resolution_event(self, advisory: dict, entity_selector: str,
                                         account_name: str, account_moid: str):
        advisory_id = advisory.get("AdvisoryId") or advisory.get("Moid", "unknown")
        properties = {
            "dt.event.correlation_tag": f"intersight-advisory-{account_moid}-{advisory_id}",
            "Advisory ID":              advisory_id,
            "Status":                   "Resolved (acknowledged or no longer applicable)",
            "Severity":                 "Info",
            "Intersight Account":       account_name,
            "Intersight Account MOID":  account_moid,
        }
        title = f"[Resolved] Cisco Advisory: {advisory.get('Name', advisory_id)[:160]}"

        self.report_dt_event(
            event_type=DtEventType.CUSTOM_ALERT,
            title=title,
            timeout=RESOLUTION_TIMEOUT_MIN,
            entity_selector=entity_selector,
            properties=properties,
        )
        self.logger.info(
            f"Sent advisory resolution event for {advisory_id} "
            f"(account={account_name}) — DT problem will close in "
            f"~{RESOLUTION_TIMEOUT_MIN} min"
        )

    def _fetch_catalog_incremental(self, base_url: str, token: str, proxy: str,
                                    api_path: str, cache_key: str,
                                    catalog_key: str,
                                    ssl_ctx: ssl.SSLContext = None) -> dict:
        """Fetch catalog incrementally using ModTime watermarks."""
        if ssl_ctx is None:
            ssl_ctx = NO_VERIFY_CTX

        with _advisory_catalog_lock:
            account_catalogs = _advisory_catalog.setdefault(cache_key, {})
            cached_map = account_catalogs.get(catalog_key)
            if cached_map is None:
                cached_map = load_advisory_catalog_from_file(cache_key, catalog_key)
                account_catalogs[catalog_key] = cached_map

        with _advisory_watermarks_lock:
            account_watermarks = _advisory_watermarks.setdefault(cache_key, {})
            if not account_watermarks:
                account_watermarks.update(load_watermarks_from_file(cache_key))
            last_modtime = account_watermarks.get(catalog_key, "")

        if last_modtime:
            self.logger.info(
                f"[{catalog_key}] Incremental fetch since {last_modtime} "
                f"(cache has {len(cached_map)} entries)"
            )
        else:
            self.logger.info(f"[{catalog_key}] First run — full fetch")

        new_items = get_advisory_definitions(base_url, token, api_path, proxy,
                                             last_modtime, ssl_ctx)

        if not new_items:
            self.logger.info(f"[{catalog_key}] No catalog changes since last poll")
            return cached_map

        new_high_water = last_modtime or "1970-01-01T00:00:00.000Z"
        for item in new_items:
            moid = item.get("Moid")
            mod_time = item.get("ModTime", "")
            if not moid:
                continue
            cached_map[moid] = item
            if mod_time > new_high_water:
                new_high_water = mod_time

        with _advisory_catalog_lock:
            _advisory_catalog[cache_key][catalog_key] = cached_map
        with _advisory_watermarks_lock:
            _advisory_watermarks[cache_key][catalog_key] = new_high_water

        threading.Thread(
            target=save_advisory_catalog_to_file,
            args=(cache_key, catalog_key, cached_map),
            daemon=True
        ).start()
        threading.Thread(
            target=save_watermarks_to_file,
            args=(cache_key, dict(_advisory_watermarks[cache_key])),
            daemon=True
        ).start()

        self.logger.info(
            f"[{catalog_key}] Merged {len(new_items)} changes; "
            f"new watermark={new_high_water}; total cached={len(cached_map)}"
        )
        return cached_map

    def _poll_advisories_endpoint(self, endpoint: dict):
        """Poll Intersight for advisory instances and emit Davis events.

        v1.2.3: distinguish brand-new accounts from known accounts (same
        logic as alarm polling) to avoid advisory close/reopen storms on
        config changes.
        """
        base_url      = _normalize_url(endpoint)
        client_id     = endpoint["client_id"]
        client_secret = endpoint["client_secret"]
        proxy         = endpoint.get("proxy", "") or ""
        host          = base_url.replace("https://", "").replace("http://", "")
        ssl_ctx       = _ssl_context_for(endpoint)

        try:
            identity = self._resolve_identity(endpoint)
        except Exception as e:
            self.logger.exception(
                f"Cannot resolve identity for advisory poll on {base_url}: {e}"
            )
            return

        account_moid = identity["moid"]
        account_name = identity["name"] or account_moid
        cache_key    = _account_cache_key(base_url, account_moid)

        # v1.2.3: a "brand-new" account here means one whose alarm cache file
        # doesn't exist on disk. The alarm file is the canonical signal that
        # the topology entity has been confirmed in some prior process.
        account_is_brand_new = not self._is_account_known(cache_key)

        advisory_hours = int(endpoint.get("advisories_poll_hours", 24) or 24)
        timeout_minutes = min((advisory_hours + 1) * 60, 6 * 60)

        try:
            token = get_token(base_url, client_id, client_secret, proxy, ssl_ctx)

            psirt_catalog = self._fetch_catalog_incremental(
                base_url, token, proxy,
                "/api/v1/tam/SecurityAdvisories", cache_key, "psirt",
                ssl_ctx=ssl_ctx,
            )
            defs_catalog = self._fetch_catalog_incremental(
                base_url, token, proxy,
                "/api/v1/tam/AdvisoryDefinitions", cache_key, "definitions",
                ssl_ctx=ssl_ctx,
            )
            catalog_lookup = {**defs_catalog, **psirt_catalog}

            instances = get_advisory_instances(base_url, token, proxy, ssl_ctx)

            type_filters = get_advisory_type_filters(endpoint)
            current = rollup_advisories(instances, catalog_lookup, type_filters)

            self.logger.info(
                f"Advisory poll {host} (account={account_name}): "
                f"{len(instances)} instances → {len(current)} unique advisories "
                f"(catalog: {len(psirt_catalog)} PSIRT + {len(defs_catalog)} FN/EOL)"
            )

            with _last_known_advisories_lock:
                previous = _last_known_advisories.get(cache_key)
                if previous is None:
                    previous = load_advisories_from_file(cache_key)
                    if previous:
                        self.logger.info(
                            f"Loaded {len(previous)} cached advisories for account {account_name}"
                        )

            previous_keys = set(previous.keys())
            current_keys  = set(current.keys())

            new_keys     = current_keys - previous_keys
            cleared_keys = previous_keys - current_keys

            # v1.2.3: defer event sending only for brand-new accounts whose
            # topology entity may not exist yet. Known accounts get events
            # immediately to avoid Davis problem timeouts on config reload.
            if account_is_brand_new:
                self.logger.info(
                    f"Brand-new account {account_name} for advisories — "
                    f"caching state but deferring events to next poll. "
                    f"({len(current)} unique advisories detected)"
                )
                with _last_known_advisories_lock:
                    _last_known_advisories[cache_key] = current
                threading.Thread(
                    target=save_advisories_to_file,
                    args=(cache_key, current),
                    daemon=True
                ).start()
                return

            entity_selector = (
                f'type(cisco:intersight_domain),'
                f'account_moid("{account_moid}")'
            )

            # Send OPEN events for new advisories
            for moid in new_keys:
                self._send_advisory_event(
                    current[moid], entity_selector,
                    account_name=account_name, account_moid=account_moid,
                    timeout_minutes=timeout_minutes,
                )

            # Send CLOSE events for resolved advisories
            for moid in cleared_keys:
                self._send_advisory_resolution_event(
                    previous[moid], entity_selector,
                    account_name=account_name, account_moid=account_moid,
                )

            # Refresh persistent advisories so they don't time out before next poll
            persistent_keys = current_keys & previous_keys
            for moid in persistent_keys:
                self._send_advisory_event(
                    current[moid], entity_selector,
                    account_name=account_name, account_moid=account_moid,
                    timeout_minutes=timeout_minutes,
                )

            # Update caches
            with _last_known_advisories_lock:
                _last_known_advisories[cache_key] = current

            threading.Thread(
                target=save_advisories_to_file,
                args=(cache_key, current),
                daemon=True
            ).start()

            self.logger.info(
                f"Advisory diff for account {account_name}: "
                f"new={len(new_keys)}, resolved={len(cleared_keys)}, "
                f"persistent={len(persistent_keys)}"
            )

        except Exception as e:
            self.logger.exception(
                f"Advisory poll failed for {base_url} (account={account_name}): {e}"
            )

    def _refresh_advisories_from_cache(self, endpoint: dict):
        """Replay cached advisories every 5h to keep Davis problems open. Zero API calls."""
        base_url = _normalize_url(endpoint)
        try:
            identity = self._resolve_identity(endpoint)
        except Exception as e:
            self.logger.warning(
                f"Advisory keepalive skipped — cannot resolve identity for {base_url}: {e}"
            )
            return

        account_moid = identity["moid"]
        account_name = identity["name"] or account_moid
        cache_key    = _account_cache_key(base_url, account_moid)

        with _last_known_advisories_lock:
            cached = dict(_last_known_advisories.get(cache_key, {}))

        if not cached:
            cached = load_advisories_from_file(cache_key)
            if cached:
                with _last_known_advisories_lock:
                    _last_known_advisories[cache_key] = cached

        if not cached:
            self.logger.info(
                f"Advisory keepalive: no cached advisories for account {account_name}"
            )
            return

        advisory_hours = int(endpoint.get("advisories_poll_hours", 24) or 24)
        timeout_minutes = min((advisory_hours + 1) * 60, 6 * 60)

        entity_selector = (
            f'type(cisco:intersight_domain),'
            f'account_moid("{account_moid}")'
        )

        for advisory in cached.values():
            self._send_advisory_event(
                advisory, entity_selector,
                account_name=account_name, account_moid=account_moid,
                timeout_minutes=timeout_minutes,
            )

        self.logger.info(
            f"Advisory keepalive refreshed {len(cached)} advisories "
            f"for account {account_name} (zero API calls)"
        )

    # ─── FASTCHECK ─────────────────────────────────────────────────────────────

    def fastcheck(self) -> Status:
        self.logger.info("fastcheck called (v1.2.3)")
        config  = self.get_activation_config()
        errors  = []
        for endpoint in config.get("endpoints", []):
            base_url      = _normalize_url(endpoint)
            client_id     = endpoint["client_id"]
            client_secret = endpoint["client_secret"]
            proxy         = endpoint.get("proxy", "") or ""
            ssl_ctx       = _ssl_context_for(endpoint)

            try:
                token    = get_token(base_url, client_id, client_secret, proxy, ssl_ctx)
                identity = fetch_account_identity(base_url, token, proxy, ssl_ctx)
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
