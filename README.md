# soc-detections — Sigma detection-as-code

> Sigma-to-OpenSearch/Wazuh detection-rule converter and manager — self-hosted, dependency-free.

Detection-content management for the SOC suite. Indexes the **SigmaHQ** rule
library, lets the SOC browse by product / category / level / ATT&CK, and converts
a rule into an **OpenSearch query** and a **Wazuh rule-XML skeleton**. Tracks which
rules are "deployed" → coverage %.

- **Rules:** [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) git submodule (DRL-1.1), ~3100 rules.
- **This app:** MIT, Python + PyYAML, port **:8103**.

## Why
Wazuh detection is hand-written XML. Sigma is the community's shared detection
language. This bridges them: pick a Sigma rule → get a ready-to-review Wazuh rule
and an OpenSearch query, and measure how much of the library you actually cover.

## Converter scope
Best-effort. Handles the common Sigma shapes: field modifiers
(`contains`/`startswith`/`endswith`/`re`), selection maps (AND), value lists (OR),
keyword lists (full-text), and conditions `sel`, `sel and/or/not sel2`,
`1 of sel*`, `all of them`, etc. Exotic conditions are flagged **unsupported**
rather than mis-translated — ~90% of rules convert. **Always review generated
Wazuh XML before loading it on a manager.**

## Run
```bash
git submodule update --init --depth 1      # fetch Sigma rules
pip install -r requirements.txt            # PyYAML
cp .env.example .env
python3 app.py                             # :8103  (index build ~9s)
```

## Deploy generated rules
"Mark deployed → write XML" writes `out/sigma_<id>.xml`. Copy it to the Wazuh
manager's `/var/ossec/etc/rules/`, then `wazuh-control restart`. Generated ids
start at `WAZUH_BASE_ID` (default 100000, the local-rules range).

## Endpoints
| Path | Purpose |
|------|---------|
| `/` | dashboard (filter, browse, convert, deploy) |
| `/api/stats` | totals, coverage %, breakdown |
| `/api/rules?product=&level=&tag=&q=` | filtered rule list |
| `/api/rule?id=` | full rule + OpenSearch query + Wazuh XML |
| `POST /api/deploy?id=` | write XML + mark deployed |
| `/health` | probe (soc-hub tile) |

## License
App: MIT. Sigma rules: Detection Rule License 1.1 (redistribution allowed).
No copyleft on this code.


## Documentation

See **[MANUAL.md](MANUAL.md)** for the full manual (overview, configuration, endpoints, integration, troubleshooting). In the running dashboard, click the **`?` Help button** in the top-right corner to open it at `/manual`.
