"""HTML report generator with evidence coverage, ATT&CK findings, and observed activity graph."""
import json
import os
from collections import defaultdict, Counter
from datetime import datetime

from .rules import SEV_SCORE, SEV_ORDER, TACTICS, catalog


def _base(p):
    return (p or "").replace("/", "\\").split("\\")[-1] or "unknown"


def host_risk_rows(findings):
    """Return explainable host risk scores derived only from actual findings."""
    weights = {"Low": 15, "Medium": 40, "High": 70, "Critical": 100}
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding["host"]].append(finding)
    rows = []
    for host, items in grouped.items():
        base_score = max(weights.get(item.get("severity"), 0) for item in items)
        count_bonus = min(25, max(0, len(items) - 1) * 5)
        tactic_bonus = min(10, max(0, len({x.get("tactic") for x in items}) - 1) * 3)
        rows.append({"host": host, "count": len(items),
                     "score": min(100, base_score + count_bonus + tactic_bonus)})
    return sorted(rows, key=lambda row: (-row["score"], row["host"]))


def telemetry_coverage(events):
    channels = Counter((ev.get("channel") or "Unknown") for ev in events)
    event_ids = Counter(((ev.get("channel") or "Unknown"), ev.get("eid")) for ev in events)
    return {
        "channels": [{"name": name, "count": count} for name, count in sorted(channels.items(), key=lambda x: (-x[1], x[0]))],
        "event_ids": [{"channel": channel, "id": str(eid), "count": count} for (channel, eid), count in sorted(event_ids.items(), key=lambda x: (-x[1], x[0][0], str(x[0][1])))],
    }

def build_graph(events, findings, limit=250):
    procs = {}
    for ev in events:
        if ev["eid"] == 1 and "sysmon" in ev["channel"].lower():
            d = ev["data"]
            g = d.get("ProcessGuid")
            if g:
                procs[g] = {"parent": d.get("ParentProcessGuid", ""), "image": d.get("Image", ""),
                            "cmd": d.get("CommandLine", ""), "host": ev["host"]}
    flagged = {}
    for f in findings:
        g = f.get("guid")
        if g in procs and f["rule_id"] != "HUNT-103":
            if g not in flagged or SEV_SCORE[f["severity"]] > SEV_SCORE[flagged[g]]:
                flagged[g] = f["severity"]
    # When there are no detections, still render the observed process tree.
    # A threat graph should not be blank merely because rules did not fire.
    keep = list(flagged)
    seen = set(keep)
    if not keep:
        keep = list(procs)[:limit]
        seen = set(keep)
    else:
        for g in list(flagged):
            p = procs[g]["parent"]
            while p in procs and p not in seen:
                seen.add(p)
                keep.append(p)
                p = procs[p]["parent"]
        for g, pr in procs.items():
            if pr["parent"] in flagged and g not in seen:
                seen.add(g)
                keep.append(g)
    keep = keep[:limit]
    ids = set(keep)
    nodes = [{"id": g, "kind": "proc", "label": _base(procs[g]["image"]), "cmd": procs[g]["cmd"],
              "host": procs[g]["host"], "sev": flagged.get(g, "")} for g in keep]
    links = [{"s": procs[g]["parent"], "t": g} for g in keep if procs[g]["parent"] in ids]
    nets = set()
    # Use observed Sysmon network-connect events when their ProcessGuid maps
    # to a process in the graph. Only real event records are used here.
    for ev in events:
        if ev["eid"] != 3 or "sysmon" not in ev["channel"].lower():
            continue
        d = ev["data"]
        guid = d.get("ProcessGuid") or d.get("ProcessGUID") or ""
        ip = d.get("DestinationIp") or d.get("DestinationIP") or ""
        port = d.get("DestinationPort") or ""
        dest = ("%s:%s" % (ip, port)).strip(":")
        if guid in ids and dest and dest not in nets:
            nets.add(dest)
            nodes.append({"id": "net:" + dest, "kind": "net", "label": dest, "cmd": "",
                          "host": ev["host"], "sev": ""})
            links.append({"s": guid, "t": "net:" + dest})
    for f in findings:
        if f["dest"] and f["guid"] in ids and f["dest"] not in nets:
            nets.add(f["dest"])
            nodes.append({"id": "net:" + f["dest"], "kind": "net", "label": f["dest"], "cmd": "", "host": f["host"],
                          "sev": f["severity"] if f["rule_id"] == "HUNT-019" else ""})
            links.append({"s": f["guid"], "t": "net:" + f["dest"]})
    return {"nodes": nodes, "links": links}


def write_report(path, source, event_count, findings, events):
    host_rows = host_risk_rows(findings)
    data = {"meta": {"source": source, "events": event_count,
                     "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            "findings": findings, "hosts": host_rows, "tactics": TACTICS, "sev": SEV_ORDER,
            "graph": build_graph(events, findings), "coverage": telemetry_coverage(events), "rules": len(catalog()), "notices": []}
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    blob = (blob.replace("&", "\\u0026").replace("<", "\\u003c")
                 .replace(">", "\\u003e").replace("\u2028", "\\u2028")
                 .replace("\u2029", "\\u2029"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE.replace("__DATA__", blob))


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SysmonHunter Report</title>
<style>
:root{--bg:#070b14;--card:#0f1626;--line:#1f2a44;--tx:#e2e8f0;--mut:#8b9bb8;--acc:#38bdf8}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#10234a 0,#070b14 60%);color:var(--tx);font:14px/1.5 Segoe UI,system-ui,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:24px}h1{margin:0;font-size:26px;letter-spacing:.5px}h1 span{color:var(--acc)}
h2{font-size:15px;text-transform:uppercase;letter-spacing:1.5px;color:var(--mut);margin:0 0 12px}
.muted{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-top:18px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;text-align:center}
.num{font-size:30px;font-weight:700;color:var(--acc)}.lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:1px}
.bar{height:10px;background:#16203a;border-radius:6px;overflow:hidden;margin-top:4px}.bar i{display:block;height:100%}
.hostrow{display:grid;grid-template-columns:260px 1fr 80px;gap:12px;align-items:center;margin:8px 0}
.matrix{display:grid;grid-template-columns:repeat(10,minmax(120px,1fr));gap:8px;overflow-x:auto}
.col{background:#0b1222;border:1px solid var(--line);border-radius:10px;padding:8px;min-height:90px}.col b{display:block;font-size:11px;color:var(--mut);text-transform:uppercase;margin-bottom:6px}
.chip{display:block;border-radius:6px;padding:3px 6px;margin:4px 0;font-size:11px;color:#fff;text-decoration:none}
.Critical{background:#ef4444}.High{background:#f97316}.Medium{background:#ca8a04}.Low{background:#16a34a}
#graph3d{position:relative;height:520px;border-radius:12px;overflow:hidden;background:#050810;border:1px solid var(--line);cursor:grab}
#tip{position:absolute;pointer-events:none;background:#0b1222ee;border:1px solid var(--line);padding:8px 10px;border-radius:8px;font-size:12px;max-width:380px;display:none;word-break:break-all;z-index:5}
.legend span{margin-right:16px}.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}
.btn{background:#16203a;border:1px solid var(--line);color:var(--tx);padding:5px 12px;border-radius:8px;cursor:pointer;margin-right:6px}.btn.on{background:var(--acc);color:#04121f}
input[type=text]{background:#0b1222;border:1px solid var(--line);color:var(--tx);padding:6px 10px;border-radius:8px;width:240px}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}th{text-align:left;color:var(--mut);font-weight:600;padding:8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid #141d33;vertical-align:top}tr.r{cursor:pointer}tr.r:hover{background:#121c33}
.badge{padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}
.det{background:#0b1222;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all}
ul.tree{list-style:none;padding-left:18px;border-left:1px dashed var(--line);margin:2px 0}ul.tree.root{border:0;padding:0}
.tn{font-family:Consolas,monospace;font-size:12px;padding:2px 0}.tn.f{color:#fca5a5;font-weight:700}
a{color:var(--acc)}
</style></head><body><div class="wrap">
<h1>Sysmon<span>Hunter</span> <span class="muted" style="font-size:14px">| Threat Hunting Report</span></h1>
<div id="meta" class="muted"></div>
<div class="stats" id="stats"></div>
<div class="card"><h2>Telemetry coverage</h2><p class="muted">Counts are calculated from the records actually ingested; missing channels or event IDs are not inferred.</p><div id="coverage"></div></div>
<div class="card"><h2>Host risk (heuristic priority)</h2><div id="hosts"></div><p class="muted">This is a triage heuristic derived from matched findings, not a probability of compromise.</p></div>
<div class="card"><h2>MITRE ATT&amp;CK coverage</h2><div class="matrix" id="matrix"></div></div>
<div class="card"><h2 id="graphTitle">Observed process and network activity graph</h2>
<div class="legend muted" style="margin-bottom:8px"><span><i style="background:#38bdf8"></i>Process</span><span><i style="background:#ef4444"></i>Critical</span><span><i style="background:#f97316"></i>High</span><span><i style="background:#eab308"></i>Medium</span><span><i style="background:#a855f7"></i>Network endpoint</span><span>Graph nodes and links are derived from ingested Sysmon records.</span></div>
<div id="graph3d"><div id="tip"></div></div></div>
<div class="card"><h2>Observed process tree</h2><div id="tree"></div></div>
<div class="card"><h2>Findings timeline</h2>
<div id="filters"></div><div style="margin-top:10px"><input type="text" id="q" placeholder="Search host, rule, command..."></div>
<table><thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Tactic</th><th>Technique</th><th>Host</th></tr></thead><tbody id="rows"></tbody></table></div>
<p class="muted" style="margin-top:20px">Generated by SysmonHunter - Project 07, Cybersecurity Blue Team Portfolio.</p>
</div>
<script>
const D = __DATA__;
const COL={Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e'};
const $=id=>document.getElementById(id);
function h(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
$('meta').textContent='Source: '+D.meta.source+'  |  Generated: '+D.meta.generated+'  |  Event timestamps: UTC  |  Rules loaded: '+D.rules;
D.notices=(D.notices||[]);D.notices.forEach(function(n){$('meta').appendChild(h('div','muted','Notice: '+n));});
const cnt={};D.sev.forEach(s=>cnt[s]=D.findings.filter(f=>f.severity===s).length);
const techs=new Set(D.findings.map(f=>f.technique).filter(t=>t&&t!=='N/A'));
[['Events analysed',D.meta.events],['Findings',D.findings.length],['Hosts affected',D.hosts.length],['Critical',cnt.Critical],['High',cnt.High],['Techniques',techs.size]].forEach(function(a){const c=h('div','stat');c.appendChild(h('div','num',a[1]));c.appendChild(h('div','lbl',a[0]));$('stats').appendChild(c);});
const cov=D.coverage||{channels:[],event_ids:[]};const cv=$('coverage');[ ['Channels',cov.channels||[]],['Event IDs',(cov.event_ids||[]).map(x=>({name:x.channel+' / Event ID '+x.id,count:x.count}))] ].forEach(function(group){const wrap=h('div','');wrap.appendChild(h('b','',group[0]));const line=h('p','muted',group[1].length?group[1].map(x=>x.name+' ('+x.count+')').join('  |  '):'No records');wrap.appendChild(line);cv.appendChild(wrap);});
if(!D.hosts.length){$('hosts').appendChild(h('p','muted','No findings were produced from the selected real event records. This is not proof that the host is clean; confirm required audit and Sysmon event sources are enabled.'));}
D.hosts.forEach(function(x){const r=h('div','hostrow');r.appendChild(h('div','',x.host+'  ('+x.count+' findings)'));const b=h('div','bar');const i=h('i');i.style.width=x.score+'%';i.style.background=x.score>75?COL.Critical:x.score>50?COL.High:x.score>25?COL.Medium:COL.Low;b.appendChild(i);r.appendChild(b);r.appendChild(h('div','',x.score+'/100'));$('hosts').appendChild(r);});
const rank={Critical:4,High:3,Medium:2,Low:1};
D.tactics.forEach(function(t){const col=h('div','col');col.appendChild(h('b','',t));const m={};
D.findings.filter(f=>f.tactic===t).forEach(function(f){const k=f.technique;if(!m[k]||rank[f.severity]>rank[m[k].sev])m[k]={sev:f.severity,n:0,name:f.name};m[k].n++;});
Object.keys(m).forEach(function(k){const a=h('a','chip '+m[k].sev,k+' x'+m[k].n);a.href='https://attack.mitre.org/techniques/'+k.replace('.','/')+'/';a.target='_blank';a.rel='noopener';a.title=m[k].name;col.appendChild(a);});
$('matrix').appendChild(col);});
if(!D.findings.length){$('matrix').appendChild(h('p','muted','No MITRE ATT&CK techniques were matched by the selected real event records.'));}
if(!D.findings.length){$('filters').appendChild(h('p','muted','No detections matched the loaded events and current rule set. Review event coverage and Sysmon configuration before drawing conclusions.'));}
let sevF='All';
function renderRows(){const q=$('q').value.toLowerCase();const tb=$('rows');tb.textContent='';
D.findings.filter(f=>(sevF==='All'||f.severity===sevF)&&(!q||JSON.stringify(f).toLowerCase().indexOf(q)>=0)).forEach(function(f){
const tr=h('tr','r');tr.appendChild(h('td','',f.time));const td=h('td');const b=h('span','badge '+f.severity,f.severity);td.appendChild(b);tr.appendChild(td);
tr.appendChild(h('td','',f.name));tr.appendChild(h('td','',f.tactic));tr.appendChild(h('td','',f.technique));tr.appendChild(h('td','',f.host));
const dr=h('tr');dr.style.display='none';const dc=h('td','det');dc.colSpan=6;
dc.textContent='ID: '+f.id+'   Rule: '+f.rule_id+'   Event ID: '+f.eid+'\nEvidence: '+f.evidence+'\nUser: '+f.user+'\nImage: '+f.image+'\nParent: '+f.parent+'\nCommand: '+f.cmd+(f.dest?'\nDestination: '+f.dest:'');
dr.appendChild(dc);tr.onclick=function(){dr.style.display=dr.style.display==='none'?'table-row':'none';};tb.appendChild(tr);tb.appendChild(dr);});}
['All'].concat(D.sev).forEach(function(s){const b=h('button','btn'+(s==='All'?' on':''),s);b.onclick=function(){sevF=s;document.querySelectorAll('#filters .btn').forEach(x=>x.classList.remove('on'));b.classList.add('on');renderRows();};$('filters').appendChild(b);});
$('q').oninput=renderRows;renderRows();
(function(){const by={};D.graph.nodes.forEach(n=>{if(n.kind==='proc')by[n.id]=Object.assign({kids:[]},n);});
D.graph.links.forEach(l=>{if(by[l.s]&&by[l.t]){by[l.t].has=true;by[l.s].kids.push(by[l.t]);}});
function node(n,d,path){const li=h('li');const t=h('div','tn'+(n.sev?' f':''),n.label+(n.sev?'  ['+n.sev+']':'')+'   '+(n.cmd||'').slice(0,110));if(n.sev)t.style.color=COL[n.sev];li.appendChild(t);
if(n.kids.length&&d<30){const ul=h('ul','tree');n.kids.forEach(k=>{if(!path.has(k.id)){const next=new Set(path);next.add(k.id);ul.appendChild(node(k,d+1,next));}});li.appendChild(ul);}return li;}
const root=h('ul','tree root');Object.values(by).filter(n=>!n.has).forEach(n=>root.appendChild(node(n,0,new Set([n.id]))));
$('tree').appendChild(root);if(!root.children.length)$('tree').textContent='No Sysmon process-creation records were present in this data set.';})();
(function(){const el=$('graph3d');
if(!D.graph.nodes.length){el.appendChild(h('p','muted','No graph data (needs Sysmon process creation events).'));return;}
const c=document.createElement('canvas');c.width=Math.max(320,el.clientWidth);c.height=520;c.style.width='100%';c.style.height='520px';el.appendChild(c);
const ctx=c.getContext('2d'),ns=D.graph.nodes,ix={};ns.forEach((n,i)=>ix[n.id]=i);
const pts=ns.map((n,i)=>{const a=i*2.399963229728653;const r=Math.sqrt((i+1)/Math.max(1,ns.length))*Math.min(c.width,c.height)*0.38;return {x:c.width/2+Math.cos(a)*r,y:c.height/2+Math.sin(a)*r,n};});
ctx.strokeStyle='#344563';ctx.lineWidth=1;D.graph.links.forEach(l=>{if(ix[l.s]===undefined||ix[l.t]===undefined)return;const a=pts[ix[l.s]],b=pts[ix[l.t]];ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();});
pts.forEach(p=>{ctx.beginPath();ctx.fillStyle=p.n.kind==='net'?'#a855f7':(COL[p.n.sev]||'#38bdf8');ctx.arc(p.x,p.y,p.n.sev?5:3.5,0,Math.PI*2);ctx.fill();});
el.appendChild(h('p','muted','Local graph rendered from observed process and network records only. No remote scripts or generated telemetry are used.'));return;
})();
</script></body></html>
"""