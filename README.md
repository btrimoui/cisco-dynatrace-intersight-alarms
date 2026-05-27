# Cisco Intersight → Dynatrace Integration
### Dynatrace Extension 2.0 | custom:cisco-intersight | v1.2.7

Polls **Cisco Intersight** alarms and security advisories, converting them into
Dynatrace Problems via the Events API v2 with full open/close lifecycle management.

> ⚠️ **ActiveGate is required.** Python EF2 extensions run exclusively on an
> Environment ActiveGate via the Extension Execution Controller (EEC).

---

## What Gets Monitored

### Alarms (full Intersight scope)
- 🔴 Hardware faults — PSU, Fan, Memory, CPU, GPU, Disk
- 📦 Failed configuration
- 🔄 Profile status anomalies — failed, out of sync
- 🔌 Target disconnection faults
- 🔑 OAuth token expiry and IAM policy violations
- 🖥️ Cisco Intersight Appliance faults (not available via SNMP)
- 📊 3× more alarms for UCS Servers vs SNMP
- 📊 2.3× more alarms for UCS IOM/Chassis vs SNMP

### Security Advisories (opt-in)
- 🛡️ **PSIRT** — Cisco Product Security Incident Response Team advisories
- 📋 **Field Notices** — Hardware/software compatibility issues
- ⏳ **End-of-Life** — Lifecycle and support deadlines

### Lifecycle Management
- **Active alarms** are reported as Dynatrace problems with a 6-hour Davis 
  timeout that survives ActiveGate restarts and prolonged maintenance windows.
- **Cleared or acknowledged alarms** are detected by diffing successive polls. 
  A resolution event is sent to close the corresponding Dynatrace problem within 
  ~1 minute.
- **Intersight outages** trigger cached refresh events to keep problems open 
  until connectivity returns.
- **Advisories** are kept open via 5-hour keepalive refresh (zero API calls), 
  preserving Davis problems between 24h advisory polls.
- **Brand-new accounts** defer event reporting to the second poll, allowing 
  the topology entity to materialize first and preventing orphaned events.

---

## Prerequisites

- Dynatrace SaaS/Managed **≥ 1.335** + Environment ActiveGate **≥ 1.335**
- Intersight OAuth2 credentials with **Read Only** role 

#### Creating Intersight OAuth2 Credentials
1. Intersight → **Settings → OAuth2 Applications → Create**
2. Grant type: **Client Credentials** | Role: **Read Only**
3. Copy **Client ID** and **Client Secret** — secret is shown only once

---

## Signing the Extension

Dynatrace requires every Python extension to be signed by a trusted Certificate 
Authority (CA) before it can be deployed. The signature is verified both by the 
Dynatrace tenant (at upload time) and by the ActiveGate (at runtime).

You have two options.

### Option 1 — Use Your Own CA (recommended for production)

For any production deployment, sign the extension with a CA that **you control**. 
This keeps the trust boundary inside your organization and makes audit/compliance 
straightforward.

### Option 2 — Use the CA Provided in This Repo

This repo ships with a `ca.pem` and a matching `developer.pem` so you can build 
and deploy without generating your own keys.

#### A. Trust the CA on your Dynatrace tenant
Settings → *Extension signing certificates* → upload `ca.pem` from this repo.

#### B. Register CA on the ActiveGate (Linux)

Copy `ca.pem` to the AG's extension trust store:

```bash
scp ca.pem root@<your-activegate>:/tmp/

# On the ActiveGate:
cp /tmp/ca.pem /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
chown root:dtuserag /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
chmod 644 /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
systemctl restart dynatracegateway
```

> **Note:** This is a one-time setup per tenant and per ActiveGate. All future 
> releases of this extension signed with the same CA will be trusted automatically.

---

## Installation

1. Download the signed `.zip` from the [Releases](https://github.com/btrimoui/cisco-dynatrace-intersight-alarms/releases) page
2. **Dynatrace Hub → Manage → Upload custom Extension 2.0** → upload the `.zip`
3. **Infrastructure → ActiveGates** → select your ActiveGate → activate `custom:cisco-intersight`

---

## Configuration

### Endpoint Settings

| Field | Required | Description | Example |
|---|---|---|---|
| **Intersight URL** | ✅ | Intersight endpoint URL | `https://eu-central-1.intersight.com` |
| **Client ID** | ✅ | OAuth2 Client ID | `6f3b2a...` |
| **Client Secret** | ✅ | OAuth2 Client Secret (encrypted) | `••••••••` |
| **Verify TLS Certificate** | ✅ | Enable for production. Disable only for self-signed appliance certs | `true` |
| **Proxy** | ❌ | HTTP/HTTPS proxy if required | `http://proxy.corp.com:8080` |

### Alarm Polling

| Field | Required | Description | Example |
|---|---|---|---|
| **Poll Interval** | ✅ | Minutes between Intersight queries (1–60) | `5` |
| **Enable Alarm Monitoring** | ✅ | Master toggle for alarms | `true` |
| **Critical / Warning / Info** | ❌ | Per-severity ingestion toggles | `Critical=on, Warning=on, Info=off` |

### Security Advisories (opt-in)

| Field | Required | Description | Example |
|---|---|---|---|
| **Enable Security Advisories** | ❌ | Master toggle for advisories | `false` (default) |
| **Advisory Poll Interval (hours)** | ❌ | Hours between advisory polls (1–168) | `24` |
| **Include PSIRT** | ❌ | Cisco Security Advisories | `true` |
| **Include Field Notices** | ❌ | Field Notices | `true` |
| **Include End-of-Life** | ❌ | EOL/EOSM notices | `true` |

> **Davis problem timeout:** Active alarm problems are kept open with a 6-hour 
> Davis timeout. This decouples problem lifetime from poll cadence, so 
> ActiveGate restarts, host maintenance, or transient network issues do not 
> trigger mass close/reopen cycles. Problems are explicitly closed via 
> resolution events the moment an alarm is cleared or acknowledged in Intersight.

---

## Outage Safety Net

If Intersight becomes unreachable, the extension reads a local alarm cache and
resends refresh events with the original correlation tags — keeping Dynatrace
Problems **open** until connectivity is restored.

```
Normal:   Poll → Save cache → Send events to DT ✅
Outage:   Poll fails → Read cache → Resend refresh events → Problems stay open ✅
Restart:  AG restart → Cache hydrates from disk → No mass close/reopen ✅
```

---

## Severity Mapping

All Dynatrace Problems created by this extension are rated **SEV-3 (Minor)** by 
Davis AI — this is a platform limitation for `CUSTOM_DEVICE` entity events and 
cannot be overridden via the event payload.

| Intersight | Dynatrace Event | Opens a Problem |
|---|---|---|
| Critical | `CUSTOM_ALERT` | ✅ Yes |
| Warning | `CUSTOM_ALERT` | ✅ Yes |
| Info | `CUSTOM_ALERT` | ✅ Yes |

> To route P1/P2 tickets correctly, configure an Alerting Profile filtering on 
> the `Severity` event property:
> **Settings → Alerting → Alerting Profiles → Filter: property `Severity` = `Critical`**

---

## Roadmap

| Version | Feature | Status |
|---|---|---|
| **v1.0.1** | Core alarm polling + outage safety net | ✅ Released |
| **v1.0.4** | Faster first-poll bootstrap, auto problem closure on clear/ack, Appliance hostname fallback | ✅ Released |
| **v1.0.5** | Cleaner event titles (account name removed from title prefix) | ✅ Released |
| **v1.1.0** | Security Advisories (PSIRT, Field Notices, End-of-Life) with incremental catalog fetch | ✅ Released |
| **v1.2.0** | TLS verification toggle, retry/backoff, paginated Intersight responses, identity caching | ✅ Released |
| **v1.2.3** | Persistent topology warmup guard — prevents mass close/reopen on AG restart | ✅ Released |
| **v1.2.6** | Per-MOID logging moved to DEBUG (~99% INFO log volume reduction) | ✅ Released |
| **v1.2.7** | 6-hour Davis problem timeout — survives AG maintenance & prolonged outages | ✅ Released |

---

## License
MIT License

---

<img width="1230" height="601" alt="image" src="https://github.com/user-attachments/assets/fd477ccf-e8c7-4d8e-9daa-ee76c09e3619" />

<img width="951" height="585" alt="image" src="https://github.com/user-attachments/assets/abde2e8c-b581-41d6-985f-2e348f838acb" />

## Building and signing

* `dt-sdk build .`

## Running

* `dt-sdk run`

## Developing

1. Clone this repository
2. Install dependencies with `pip install .`
3. Increase the version under `extension/extension.yaml` after modifications
4. Run `dt-sdk build`

## Structure

### cisco_intersight folder
Contains the Python code for the extension.

### extension folder
Contains the YAML and activation definitions for the framework v2 extension.

### setup.py
Contains dependency and other Python metadata.

### activation.json
Used during simulation only — contains the activation definition for the extension.
