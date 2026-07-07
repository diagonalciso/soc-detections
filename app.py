#!/usr/bin/env python3
"""soc-detections — detection-as-code (Sigma rule library + converter).

Indexes the bundled SigmaHQ rule set (git submodule `sigma/`, DRL-1.1), lets the
SOC browse by product / category / level / ATT&CK, and converts a rule's Sigma
detection logic into (a) an OpenSearch bool query and (b) a Wazuh rule-XML
skeleton. Tracks which rules are marked "deployed" -> coverage %.

Converter is best-effort: it handles the common Sigma shapes (field modifiers,
selection maps, keyword lists, and the usual `condition` forms). Anything exotic
is flagged unsupported rather than mis-converted — always review before shipping
generated Wazuh rules to a manager.

Deps: PyYAML. Run: cp .env.example .env && python3 app.py  (:8103)
"""
import glob
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import yaml

SIGMA_DIR = os.getenv("SIGMA_DIR", os.path.join(os.path.dirname(__file__), "sigma", "rules"))
OUT_DIR = os.getenv("WAZUH_OUT_DIR", os.path.join(os.path.dirname(__file__), "out"))
DB_PATH = os.getenv("DET_DB", os.path.join(os.path.dirname(__file__), "detections.db"))
PORT = int(os.getenv("DET_PORT", "8103"))
HOST = os.getenv("DET_HOST", "0.0.0.0")
WAZUH_BASE_ID = int(os.getenv("WAZUH_BASE_ID", "100000"))

# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_index = {}          # id -> meta dict
_state = {"ready": False, "count": 0, "started": time.time()}


def _init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS deployed (rule_id TEXT PRIMARY KEY, "
              "title TEXT, deployed_at TEXT)")
    c.commit()
    c.close()


def _attack_tags(tags):
    tactics, techniques = [], []
    for t in tags or []:
        t = str(t)
        if t.startswith("attack."):
            v = t.split("attack.", 1)[1]
            if re.fullmatch(r"t\d{4}(\.\d{3})?", v):
                techniques.append(v.upper())
            else:
                tactics.append(v.replace("_", "-"))
    return tactics, techniques


def _build_index():
    idx = {}
    for path in glob.glob(os.path.join(SIGMA_DIR, "**", "*.yml"), recursive=True):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        rid = doc.get("id") or hashlib.md5(path.encode()).hexdigest()
        ls = doc.get("logsource", {}) or {}
        tactics, techniques = _attack_tags(doc.get("tags"))
        idx[rid] = {
            "id": rid,
            "title": doc.get("title", "(untitled)"),
            "level": doc.get("level", "unknown"),
            "status": doc.get("status", ""),
            "product": ls.get("product", ""),
            "category": ls.get("category", ""),
            "service": ls.get("service", ""),
            "tactics": tactics,
            "techniques": techniques,
            "path": path,
        }
    with _lock:
        _index.clear()
        _index.update(idx)
        _state["ready"] = True
        _state["count"] = len(idx)


def _load_rule(rid):
    meta = _index.get(rid)
    if not meta:
        return None
    try:
        with open(meta["path"], "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Sigma -> OpenSearch  (best effort)
# --------------------------------------------------------------------------- #
_MODIFIER_WILDCARD = {"contains": ("*", "*"), "startswith": ("", "*"),
                      "endswith": ("*", "")}


def _leaf_query(field, modifiers, value):
    """One field:value(+modifier) -> an OpenSearch query clause."""
    value = "" if value is None else str(value)
    if "re" in modifiers:
        return {"regexp": {field: value}}
    if any(m in _MODIFIER_WILDCARD for m in modifiers):
        for m in modifiers:
            if m in _MODIFIER_WILDCARD:
                pre, post = _MODIFIER_WILDCARD[m]
                esc = value.replace("*", "\\*").replace("?", "\\?")
                return {"wildcard": {field: f"{pre}{esc}{post}"}}
    return {"match_phrase": {field: value}}


def _field_clause(key, value):
    """`Field|mods: value|list` -> clause (OR over a list of values)."""
    parts = key.split("|")
    field = parts[0]
    modifiers = parts[1:]
    if isinstance(value, list):
        shoulds = [_leaf_query(field, modifiers, v) for v in value]
        return {"bool": {"should": shoulds, "minimum_should_match": 1}}
    return _leaf_query(field, modifiers, value)


def _selection_query(sel):
    """A selection block -> query.  dict=AND of fields; list=OR of sub-maps;
    bare list of scalars=keyword OR (full-text)."""
    if isinstance(sel, dict):
        musts = [_field_clause(k, v) for k, v in sel.items()]
        return {"bool": {"must": musts}} if len(musts) != 1 else musts[0]
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):        # OR of maps
            return {"bool": {"should": [_selection_query(x) for x in sel],
                             "minimum_should_match": 1}}
        # keyword list -> full-text OR
        return {"bool": {"should": [{"query_string": {"query": f"*{k}*"}} for k in sel],
                         "minimum_should_match": 1}}
    return {"query_string": {"query": str(sel)}}


def sigma_to_opensearch(doc):
    """Return (query_dict, supported_bool, note)."""
    det = doc.get("detection", {}) or {}
    cond = str(det.get("condition", "")).strip()
    sels = {k: v for k, v in det.items() if k != "condition"}
    if not cond or not sels:
        return None, False, "empty detection"

    built = {k: _selection_query(v) for k, v in sels.items()}

    def _wild(name_glob):
        pre = name_glob.replace("*", "")
        return [built[k] for k in built if k.startswith(pre)]

    # handle the common condition grammar
    try:
        # 1 of / all of  (them | selection_*)
        m = re.fullmatch(r"(1|all) of (them|[\w*]+)", cond)
        if m:
            quant, tgt = m.group(1), m.group(2)
            clauses = list(built.values()) if tgt == "them" else _wild(tgt)
            if not clauses:
                return None, False, f"no selections match '{tgt}'"
            if quant == "all":
                return {"bool": {"must": clauses}}, True, ""
            return {"bool": {"should": clauses, "minimum_should_match": 1}}, True, ""

        # simple boolean expr over selection names with optional 'not'
        if re.fullmatch(r"[\w\s()]+(and|or|not)[\w\s()]+|[\w]+", cond) and \
           " of " not in cond:
            must, must_not, should = [], [], []
            tokens = cond.replace("(", " ").replace(")", " ").split()
            i, op = 0, "and"
            neg = False
            while i < len(tokens):
                tok = tokens[i]
                if tok in ("and", "or"):
                    op = tok
                elif tok == "not":
                    neg = True
                elif tok in built:
                    clause = built[tok]
                    if neg:
                        must_not.append(clause)
                        neg = False
                    elif op == "or":
                        should.append(clause)
                    else:
                        must.append(clause)
                i += 1
            b = {}
            if must:
                b["must"] = must
            if must_not:
                b["must_not"] = must_not
            if should:
                b["should"] = should
                b["minimum_should_match"] = 1
            if b:
                return {"bool": b}, True, ""
    except Exception as e:
        return None, False, f"parse error: {e}"

    return None, False, f"unsupported condition: {cond!r}"


def sigma_to_wazuh(doc, rid):
    """Skeleton Wazuh local rule. Deterministic id from sigma id. Review before use."""
    det = doc.get("detection", {}) or {}
    level = doc.get("level", "medium")
    wz_level = {"critical": 14, "high": 12, "medium": 7, "low": 5,
                "informational": 3}.get(level, 7)
    num = WAZUH_BASE_ID + (int(hashlib.md5(rid.encode()).hexdigest(), 16) % 90000)
    fields = []
    for k, v in det.items():
        if k == "condition" or not isinstance(v, dict):
            continue
        for fk, fv in v.items():
            fname = fk.split("|")[0]
            vals = fv if isinstance(fv, list) else [fv]
            pat = "|".join(re.escape(str(x)) for x in vals)
            fields.append(f'    <field name="{fname}" type="pcre2">{pat}</field>')
    body = "\n".join(fields) or "    <!-- unmapped detection: translate manually -->"
    tags = " ".join(doc.get("tags", []))
    return (f'<group name="sigma,soc-detections,">\n'
            f'  <rule id="{num}" level="{wz_level}">\n'
            f'    <description>{doc.get("title","")}</description>\n'
            f'{body}\n'
            f'    <info type="link">sigma id {rid}</info>\n'
            f'    <!-- ATT&CK: {tags} -->\n'
            f'  </rule>\n'
            f'</group>\n')


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _deployed_ids():
    c = sqlite3.connect(DB_PATH)
    rows = [r[0] for r in c.execute("SELECT rule_id FROM deployed")]
    c.close()
    return set(rows)


def _stats():
    with _lock:
        rules = list(_index.values())
    by_product, by_level = {}, {}
    for r in rules:
        by_product[r["product"] or "(none)"] = by_product.get(r["product"] or "(none)", 0) + 1
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
    dep = _deployed_ids()
    return {
        "ready": _state["ready"],
        "total": len(rules),
        "deployed": len(dep),
        "coverage_pct": round(100 * len(dep) / len(rules), 1) if rules else 0,
        "by_product": dict(sorted(by_product.items(), key=lambda x: -x[1])),
        "by_level": by_level,
    }


def _list(q):
    prod = (q.get("product", [""])[0] or "").lower()
    level = (q.get("level", [""])[0] or "").lower()
    tag = (q.get("tag", [""])[0] or "").lower()
    text = (q.get("q", [""])[0] or "").lower()
    limit = int(q.get("limit", ["200"])[0])
    dep = _deployed_ids()
    out = []
    with _lock:
        rules = list(_index.values())
    for r in rules:
        if prod and r["product"].lower() != prod:
            continue
        if level and r["level"].lower() != level:
            continue
        if tag and tag not in [t.lower() for t in r["tactics"] + r["techniques"]]:
            continue
        if text and text not in r["title"].lower():
            continue
        out.append({**r, "deployed": r["id"] in dep})
        if len(out) >= limit:
            break
    out.sort(key=lambda x: x["title"].lower())
    return out


PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Soc-Detections — Sigma Detection-as-Code</title><style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--txt:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--ok:#3fb950;--crit:#f85149;--hi:#f0883e;--med:#d29922}
*{box-sizing:border-box}body{margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid var(--bd);background:var(--panel)}
h1{margin:0;font-size:18px;letter-spacing:1px;color:var(--accent)}h1 small{font-weight:400;opacity:.55;font-size:.6em;color:var(--txt)}
.meta{font-size:12px;color:var(--dim);text-align:right}
.wrap{max-width:1300px;margin:0 auto;padding:18px;display:grid;grid-template-columns:340px 1fr;gap:16px}
.kpis{grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:12px}
.kpi .n{font-size:24px;font-weight:700;color:var(--accent)}.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:14px}
input,select{background:#0a1020;border:1px solid var(--bd);color:var(--txt);padding:7px 9px;border-radius:6px;width:100%;margin-bottom:8px;font-family:inherit}
.rule{padding:8px 10px;border:1px solid var(--bd);border-radius:6px;margin-bottom:6px;cursor:pointer;font-size:12px}
.rule:hover{border-color:var(--accent)}.rule .lv{float:right;font-size:10px;text-transform:uppercase}
.critical{color:var(--crit)}.high{color:var(--hi)}.medium{color:var(--med)}.low{color:var(--dim)}
.badge{display:inline-block;background:#1a2440;border-radius:4px;padding:1px 6px;font-size:10px;margin-right:4px;color:var(--dim)}
pre{background:#0a1020;border:1px solid var(--bd);border-radius:6px;padding:10px;overflow:auto;font-size:11px;max-height:280px}
button{background:var(--accent);color:#fff;border:none;border-radius:6px;padding:8px 14px;cursor:pointer;font-family:inherit}
button:hover{opacity:.9}.ok{color:var(--ok)}.bad{color:var(--hi)}
h2{font-size:13px;color:var(--accent);text-transform:uppercase;letter-spacing:1px;margin:0 0 10px}
.dep{color:var(--ok);font-size:10px}
</style></head><body><a href="/manual" target="_blank" title="Manual / Help" style="position:fixed;top:12px;right:14px;z-index:99999;width:30px;height:30px;border-radius:50%;background:#161b22;border:1px solid #30363d;color:#58a6ff;font:700 16px/30px system-ui,sans-serif;text-align:center;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.4)" onmouseover="this.style.borderColor='#58a6ff'" onmouseout="this.style.borderColor='#30363d'">?</a>
<header><h1>SOC-DETECTIONS <small>Sigma · detection-as-code</small></h1>
<div class="meta" id="meta">loading…</div></header>
<div class="wrap">
  <div class="kpis">
    <div class="kpi"><div class="n" id="k-total">--</div><div class="l">Sigma rules</div></div>
    <div class="kpi"><div class="n" id="k-dep">--</div><div class="l">Deployed</div></div>
    <div class="kpi"><div class="n" id="k-cov">--</div><div class="l">Coverage</div></div>
    <div class="kpi"><div class="n" id="k-prod">--</div><div class="l">Products</div></div>
  </div>
  <div class="panel">
    <h2>Filter</h2>
    <input id="f-q" placeholder="search title…" oninput="reload()">
    <select id="f-product" onchange="reload()"><option value="">all products</option></select>
    <select id="f-level" onchange="reload()">
      <option value="">all levels</option><option>critical</option><option>high</option>
      <option>medium</option><option>low</option><option>informational</option></select>
    <input id="f-tag" placeholder="ATT&amp;CK tag e.g. t1059 / execution" oninput="reload()">
    <div id="count" class="dim" style="font-size:11px;margin-top:6px"></div>
    <div id="list" style="margin-top:8px;max-height:60vh;overflow:auto"></div>
  </div>
  <div class="panel" id="detail"><h2>Rule detail</h2><div class="dim">select a rule →</div></div>
</div>
<script>
const $=s=>document.querySelector(s);
async function stats(){
  const s=await (await fetch('/api/stats')).json();
  $('#k-total').textContent=s.total;$('#k-dep').textContent=s.deployed;
  $('#k-cov').textContent=s.coverage_pct+'%';$('#k-prod').textContent=Object.keys(s.by_product).length;
  $('#meta').textContent=s.ready?('indexed '+s.total+' rules'):'indexing…';
  const sel=$('#f-product');
  if(sel.options.length<=1){for(const p of Object.keys(s.by_product)){const o=document.createElement('option');o.value=p;o.textContent=p+' ('+s.by_product[p]+')';sel.appendChild(o);}}
  if(!s.ready)setTimeout(stats,1500);
}
async function reload(){
  const p=new URLSearchParams({q:$('#f-q').value,product:$('#f-product').value,level:$('#f-level').value,tag:$('#f-tag').value});
  const rows=await (await fetch('/api/rules?'+p)).json();
  $('#count').textContent=rows.length+' shown';
  $('#list').innerHTML=rows.map(r=>`<div class="rule" onclick="detail('${r.id}')">
    <span class="lv ${r.level}">${r.level}</span>${esc(r.title)}
    ${r.deployed?'<span class="dep">● live</span>':''}<br>
    <span class="badge">${r.product||'—'}</span><span class="badge">${r.category||''}</span>
    ${r.techniques.slice(0,3).map(t=>'<span class="badge">'+t+'</span>').join('')}</div>`).join('')||'<div class="dim">no matches</div>';
}
async function detail(id){
  const d=await (await fetch('/api/rule?id='+encodeURIComponent(id))).json();
  $('#detail').innerHTML=`<h2>Rule detail</h2>
    <b>${esc(d.meta.title)}</b> <span class="${d.meta.level}">[${d.meta.level}]</span><br>
    <span class="badge">${d.meta.product||'—'}</span><span class="badge">${d.meta.category||''}</span>
    ${d.meta.techniques.map(t=>'<span class="badge">'+t+'</span>').join('')}
    <p style="font-size:12px;color:var(--dim)">${esc(d.description||'')}</p>
    <div>OpenSearch query ${d.supported?'<span class="ok">✓ supported</span>':'<span class="bad">⚠ '+esc(d.note)+'</span>'}</div>
    <pre>${esc(JSON.stringify(d.opensearch,null,2))}</pre>
    <div>Wazuh rule skeleton <span class="dim">(review before deploy)</span></div>
    <pre>${esc(d.wazuh)}</pre>
    <button onclick="deploy('${d.meta.id}')">${d.deployed?'Re-mark deployed':'Mark deployed → write XML'}</button>
    <span id="depmsg" class="ok" style="margin-left:10px"></span>`;
}
async function deploy(id){
  const r=await (await fetch('/api/deploy?id='+encodeURIComponent(id),{method:'POST'})).json();
  $('#depmsg').textContent=r.ok?('written '+r.file):'error';stats();reload();
}
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
stats();reload();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        if self.path.split("?")[0].rstrip("/") == "/manual":
            _serve_manual(self); return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif u.path == "/api/stats":
            self._send(200, "application/json", json.dumps(_stats()))
        elif u.path == "/api/rules":
            self._send(200, "application/json", json.dumps(_list(q)))
        elif u.path == "/api/rule":
            rid = q.get("id", [""])[0]
            doc = _load_rule(rid)
            if not doc:
                return self._send(404, "application/json", json.dumps({"error": "not found"}))
            osq, sup, note = sigma_to_opensearch(doc)
            self._send(200, "application/json", json.dumps({
                "meta": _index.get(rid),
                "description": doc.get("description", ""),
                "opensearch": osq or {},
                "supported": sup, "note": note,
                "wazuh": sigma_to_wazuh(doc, rid),
                "deployed": rid in _deployed_ids(),
            }))
        elif u.path == "/health":
            self._send(200, "application/json",
                       json.dumps({"status": "ok", "ready": _state["ready"],
                                   "total": _state["count"]}))
        else:
            self._send(404, "text/plain", "not found")

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/deploy":
            rid = q.get("id", [""])[0]
            doc = _load_rule(rid)
            if not doc:
                return self._send(404, "application/json", json.dumps({"ok": False}))
            os.makedirs(OUT_DIR, exist_ok=True)
            fname = os.path.join(OUT_DIR, f"sigma_{rid}.xml")
            with open(fname, "w", encoding="utf-8") as f:
                f.write(sigma_to_wazuh(doc, rid))
            c = sqlite3.connect(DB_PATH)
            c.execute("INSERT OR REPLACE INTO deployed VALUES (?,?,?)",
                      (rid, doc.get("title", ""), datetime.now(timezone.utc).isoformat()))
            c.commit()
            c.close()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "file": os.path.basename(fname)}))
        else:
            self._send(404, "text/plain", "not found")

    def log_message(self, *a):
        pass




# ---- injected: /manual help page (stdlib markdown renderer) ----------------
def _md_to_html(md):
    import html, re as _re
    lines = md.split("\n")
    out = []; i = 0; n = len(lines)
    def inline(t):
        t = html.escape(t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        t = _re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                    r'<a href="\2" target="_blank" rel="noopener">\1</a>', t)
        return t
    while i < n:
        ln = lines[i]
        if ln.startswith("```"):
            i += 1; buf = []
            while i < n and not lines[i].startswith("```"):
                buf.append(html.escape(lines[i])); i += 1
            i += 1
            out.append("<pre><code>" + "\n".join(buf) + "</code></pre>"); continue
        m = _re.match(r"(#{1,6})\s+(.*)", ln)
        if m:
            lv = len(m.group(1)); out.append("<h%d>%s</h%d>" % (lv, inline(m.group(2)), lv)); i += 1; continue
        if _re.match(r"\s*[-*]\s+", ln):
            out.append("<ul>")
            while i < n and _re.match(r"\s*[-*]\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*[-*]\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ul>"); continue
        if _re.match(r"\s*\d+\.\s+", ln):
            out.append("<ol>")
            while i < n and _re.match(r"\s*\d+\.\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*\d+\.\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ol>"); continue
        if ln.strip().startswith("|") and i + 1 < n and _re.match(r"^\s*\|[-:\s|]+\|\s*$", lines[i+1]):
            hdr = [c.strip() for c in ln.strip().strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join("<th>%s</th>" % inline(c) for c in hdr) + "</tr></thead><tbody>")
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in cells) + "</tr>"); i += 1
            out.append("</tbody></table>"); continue
        if _re.match(r"^\s*---+\s*$", ln):
            out.append("<hr>"); i += 1; continue
        if ln.strip() == "":
            i += 1; continue
        para = [ln]; i += 1
        while i < n and lines[i].strip() and not _re.match(r"(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s|\|)", lines[i]):
            para.append(lines[i]); i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")
    return "\n".join(out)


def _manual_page(inner):
    return ("""<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Manual</title><style>
:root{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--ac:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:15px/1.65 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 22px 80px}
.top{position:sticky;top:0;background:rgba(13,17,23,.92);backdrop-filter:blur(6px);
border-bottom:1px solid var(--bd);margin:-32px -22px 24px;padding:12px 22px;display:flex;
align-items:center;gap:12px}
.top a{color:var(--ac);text-decoration:none;font-size:13px}
h1,h2,h3,h4{color:#fff;line-height:1.25;margin:1.5em 0 .5em}
h1{font-size:26px;border-bottom:1px solid var(--bd);padding-bottom:.3em}
h2{font-size:20px;border-bottom:1px solid var(--bd);padding-bottom:.25em}
h3{font-size:16px}a{color:var(--ac)}
code{background:var(--sf);border:1px solid var(--bd);border-radius:4px;padding:1px 5px;
font:13px/1.4 ui-monospace,Menlo,monospace}
pre{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;
overflow:auto}pre code{background:none;border:0;padding:0}
ul,ol{padding-left:1.4em}li{margin:.25em 0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:14px}
th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left}
th{background:var(--sf)}hr{border:0;border-top:1px solid var(--bd);margin:2em 0}
.mut{color:var(--mut)}
</style></head><body><div class=wrap>
<div class=top><a href="/">&larr; Back to app</a><span class=mut>&middot; Manual</span></div>
""" + inner + "\n</div></body></html>")


def _serve_manual(handler):
    import os as _os
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "MANUAL.md")
    try:
        with open(p, encoding="utf-8") as _fh:
            md = _fh.read()
    except OSError:
        md = "# Manual\n\nMANUAL.md not found next to the application."
    body = _manual_page(_md_to_html(md)).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
# ---- end injected block -----------------------------------------------------

if __name__ == "__main__":
    _init_db()
    threading.Thread(target=_build_index, daemon=True).start()
    print(f"soc-detections on http://{HOST}:{PORT}  (sigma={SIGMA_DIR})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
