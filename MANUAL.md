# soc-Detections — Detection-as-Code (Sigma)

> Browse, convert and deploy Sigma rules to Wazuh / OpenSearch.

**Port:** `8103` &nbsp;|&nbsp; **Repo:** `diagonalciso/soc-detections` &nbsp;|&nbsp; **Service:** `soc-detections.service` &nbsp;|&nbsp; **Stack:** stdlib Python (no external deps)

Part of the **CD / Wazuh Full SOC** suite. Open the in-app **`?` Help button** (top-right of the dashboard) to read this manual, or view it here.

---

## 1. Overview

soc-Detections turns the community Sigma ruleset into deployable detections. It loads Sigma YAML rules, lets you browse them by ATT&CK technique and logsource, previews the converted backend query, and deploys the rule either as Wazuh rule XML or as an OpenSearch monitor. It tracks which rules are live versus merely available, giving a detection-coverage percentage so you can see blind spots at a glance.

## 2. Key features

- Browse the Sigma rule library by ATT&CK technique and logsource
- Preview the converted OpenSearch query or Wazuh rule XML before deploying
- Enable / disable rules; deploy to Wazuh (writes rule XML + reload) or OpenSearch
- Coverage view: live vs available rules as a percentage
- Requires PyYAML (installed by the suite)

## 3. Running the service

The service is a single self-contained `app.py` using only the Python standard library.

```bash
# systemd (fleet / suite install)
sudo systemctl status soc-detections
sudo systemctl restart soc-detections
sudo journalctl -u soc-detections -f

# manual run (from the repo directory)
cp .env.example .env      # then edit as needed
env $(grep -v '^#' .env | xargs) python3 app.py
```

Then open **http://<host>:8103/**.

## 4. Configuration (environment variables)

Set these in `.env` (see `.env.example` for defaults):

| Variable | Notes |
|---|---|
| `DET_DB` |  |
| `DET_HOST` |  |
| `DET_PORT` | Listen port (default 8103). |
| `SIGMA_DIR` |  |
| `WAZUH_BASE_ID` |  |
| `WAZUH_OUT_DIR` |  |

## 5. HTTP endpoints

| Path | |
|---|---|
| `/` | Main dashboard (HTML) |
| `/api/deploy` | API endpoint (JSON) |
| `/api/rule` | API endpoint (JSON) |
| `/api/rules` | API endpoint (JSON) |
| `/api/stats` | API endpoint (JSON) |
| `/health` | Health check |
| `/manual` | This manual (opened by the top-right **?** Help button) |

## 6. Integration

Deploys detections into the Wazuh manager (rule XML) and/or OpenSearch monitors. Pairs with soc-validate to prove deployed rules actually fire.

## 7. Security & operational notes

Sigma→Wazuh mapping is best-effort; start with linux/windows process & auth rules and expand. Deploying rules restarts the Wazuh manager — schedule accordingly.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Page will not load | `systemctl status soc-detections`; confirm the port `8103` is listening (`lsof -i:8103`). |
| Help button shows "MANUAL.md not found" | Ensure `MANUAL.md` sits next to `app.py` in the service directory. |
| Service keeps restarting | `journalctl -u soc-detections -e` for the traceback; usually a missing `.env` value. |
| Empty / stale data | Confirm upstream sources and any API keys in `.env` are reachable. |

---

*Manual for soc-detections. Part of the CD / Wazuh Full SOC suite. Private © CisoDiagonal.*
