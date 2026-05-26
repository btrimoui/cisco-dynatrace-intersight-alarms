# Cisco Intersight → Dynatrace Integration
### Dynatrace Extension 2.0 | custom:cisco-intersight | v1.0.5

Polls **Cisco Intersight** alarms and converts them into Dynatrace Problems 
via the Events API v2, with full open/close lifecycle management.

> ⚠️ **ActiveGate is required.** Python EF2 extensions run exclusively on an
> Environment ActiveGate via the Extension Execution Controller (EEC).

---

## What Gets Monitored

This extension covers the full alarm scope:

- 🔴 Hardware faults — PSU, Fan, Memory, CPU, GPU, Disk
- 📦 Failed configuration
- 🔄 Profile status anomalies — failed, out of sync
- 🔌 Target disconnection faults
- 🔑 OAuth token expiry and IAM policy violations
- 🖥️ Cisco Intersight Appliance faults (not available via SNMP)
- 📊 3x more alarms for UCS Servers available via REST API vs SNMP
- 📊 2.3x more alarms for UCS IOM/Chassis available via REST API vs SNMP


### Lifecycle Management

- **Active alarms** are reported as Dynatrace problems and refreshed on every poll.
- **Cleared or acknowledged alarms** are detected by diffing successive polls. A 
  resolution event is sent to close the corresponding Dynatrace problem within ~1 minute.
- **Intersight outages** trigger cached refresh events to keep problems open until 
  connectivity returns.

---

## Prerequisites

- Dynatrace SaaS/Managed **≥ 1.335** + Environment ActiveGate **≥ 1.335**
- Intersight OAuth2 credentials with **Read Only** role 

#### Creating Intersight OAuth2 Credentials
1. Intersight → **Settings → OAuth2 Applications → Create**
2. Grant type: **Client Credentials** | Role: **Read Only**
3. Copy **Client ID** and **Client Secret** — secret is shown only once

---

## Trust Setup (one-time per Dynatrace tenant)

The signed extension is verified by Dynatrace against trusted root certificates. Before installing, register this extension's CA certificate in your Dynatrace tenant **and** on each ActiveGate that will run the extension.

### A. Register CA in your Dynatrace tenant

1. Download the CA certificate: [`ca.pem`](https://github.com/btrimoui/cisco-dynatrace-intersight-alarms/blob/main/ca.pem) from this repo
2. In Dynatrace UI: **Settings → search "Extension signing"** → upload `ca.pem` as a trusted root certificate

### B. Register CA on the ActiveGate (Linux)

Copy `ca.pem` to the AG's extension trust store:

```bash
scp ca.pem root@<your-activegate>:/tmp/

# On the ActiveGate:
cp /tmp/ca.pem /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
chown root:dtuserag /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
chmod 644 /var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/cisco-intersight-ca.pem
systemctl restart dynatracegateway
```

> **Note:** This is a one-time setup per tenant and per ActiveGate. All future releases of this extension signed with the same CA will be trusted automatically.

---

## Installation

1. Download the signed `.zip` from the [Releases](https://github.com/btrimoui/cisco-dynatrace-intersight-alarms/releases) page
2. **Dynatrace Hub → Manage → Upload custom Extension 2.0** → upload the `.zip`
3. **Infrastructure → ActiveGates** → select your ActiveGate → activate `custom:cisco-intersight`

---

## Configuration

| Field | Required | Description | Example |
|---|---|---|---|
| **URL** | ✅ | Intersight endpoint URL | `https://intersight.com` |
| **Client ID** | ✅ | OAuth2 Client ID | `6f3b2a...` |
| **Client Secret** | ✅ | OAuth2 Client Secret (encrypted) | `••••••••` |
| **Proxy** | ❌ | HTTP proxy if required | `http://proxy.corp.com:80` |
| **Poll Interval** | ✅ | Minutes between polls | `5` |
| **Critical / Warning / Info** | ❌ | Per-severity ingestion toggles | `true` |
| **Alarm Timeout** | ✅ | Minutes before unseen alarm closes | `10` |

---

## Outage Safety Net

If Intersight becomes unreachable, the extension reads a local alarm cache and
resends refresh events with the original correlation tags — keeping Dynatrace
Problems **open** until connectivity is restored.

Normal: Poll → Save cache → Send events to DT ✅
Outage: Poll fails → Read cache → Resend refresh events → Problems stay open ✅

---

## Severity Mapping

All Dynatrace Problems created by this extension are rated **SEV-3 (Minor)** by 
Davis AI — this is a platform limitation for `CUSTOM_DEVICE` entity events and 
cannot be overridden via the event payload.

| Intersight | Dynatrace Event | Opens a Problem |
|---|---|---|
| Critical | `CUSTOM_ALERT` | ✅ Yes |
| Warning | `CUSTOM_ALERT` | ✅ Yes |
| Info | `CUSTOM_INFO` | ✅ Yes |

> To route P1/P2 tickets correctly, configure an Alerting Profile filtering on 
> the `Severity` event property:
> **Settings → Alerting → Alerting Profiles → Filter: property `Severity` = `Critical`**

---

## Roadmap

| Version | Feature | Target |
|---|---|---|
| **v1.0.1** | Core alarms polling + outage safety net | ✅ Released |
| **v1.0.4** | Faster first-poll bootstrap, automatic problem closure on cleared/acknowledged alarms, Appliance hostname fallback | ✅ Released |
| **v1.0.5** | Cleaner event titles (account name removed from title prefix) | ✅ Release
| **v1.1.0** | Security Advisories + Field Notices | Q3 2026 |

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

Contains the python code for the extension

### extension folder

Contains the yaml and activation definitions for the framework v2 extension

### setup.py

Contains dependency and other python metadata

### activation.json

Used during simulation only, contains the activation definition for the extension
