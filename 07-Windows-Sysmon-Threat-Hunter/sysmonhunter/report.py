"""HTML report generator with ATT&CK matrix and an interactive 3D attack graph."""
import json
import os
from collections import defaultdict
from datetime import datetime

from .rules import SEV_SCORE, SEV_ORDER, TACTICS, catalog


def _base(p):
    return (p or "").replace("/", "\\").split("\\")[-1] or "unknown"


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
    keep = list(flagged)
    seen = set(keep)
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
    for f in findings:
        if f["dest"] and f["guid"] in ids and f["dest"] not in nets:
            nets.add(f["dest"])
            nodes.append({"id": "net:" + f["dest"], "kind": "net", "label": f["dest"], "cmd": "", "host": f["host"],
                          "sev": f["severity"] if f["rule_id"] == "HUNT-019" else ""})
            links.append({"s": f["guid"], "t": "net:" + f["dest"]})
    return {"nodes": nodes, "links": links}


def write_report(path, source, event_count, findings, events):
    hosts = defaultdict(list)
    for f in findings:
        hosts[f["host"]].append(SEV_SCORE[f["severity"]])
    host_rows = sorted(({"host": h, "count": len(v), "score": min(100, sum(v) // 2)} for h, v in hosts.items()),
                       key=lambda x: -x["score"])
    data = {"meta": {"source": source, "events": event_count,
                     "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            "findings": findings, "hosts": host_rows, "tactics": TACTICS, "sev": SEV_ORDER,
            "graph": build_graph(events, findings), "rules": len(catalog())}
    blob = json.dumps(data).replace("</", "<\\/")
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
<div class="card"><h2>Host risk</h2><div id="hosts"></div></div>
<div class="card"><h2>MITRE ATT&amp;CK coverage</h2><div class="matrix" id="matrix"></div></div>
<div class="card"><h2>3D attack graph</h2>
<div class="legend muted" style="margin-bottom:8px"><span><i style="background:#38bdf8"></i>Process</span><span><i style="background:#ef4444"></i>Critical</span><span><i style="background:#f97316"></i>High</span><span><i style="background:#eab308"></i>Medium</span><span><i style="background:#a855f7"></i>External IP</span><span>Drag = rotate | Wheel = zoom | Hover = details</span></div>
<div id="graph3d"><div id="tip"></div></div></div>
<div class="card"><h2>Process tree (flagged chains)</h2><div id="tree"></div></div>
<div class="card"><h2>Findings timeline</h2>
<div id="filters"></div><div style="margin-top:10px"><input type="text" id="q" placeholder="Search host, rule, command..."></div>
<table><thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Tactic</th><th>Technique</th><th>Host</th></tr></thead><tbody id="rows"></tbody></table></div>
<p class="muted" style="margin-top:20px">Generated by SysmonHunter - Project 07, Cybersecurity Blue Team Portfolio.</p>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
const D = __DATA__;
const COL={Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e'};
const $=id=>document.getElementById(id);
function h(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
$('meta').textContent='Source: '+D.meta.source+'  |  Generated: '+D.meta.generated+'  |  Rules loaded: '+D.rules;
const cnt={};D.sev.forEach(s=>cnt[s]=D.findings.filter(f=>f.severity===s).length);
const techs=new Set(D.findings.map(f=>f.technique));
[['Events analysed',D.meta.events],['Findings',D.findings.length],['Hosts affected',D.hosts.length],['Critical',cnt.Critical],['High',cnt.High],['Techniques',techs.size]].forEach(function(a){const c=h('div','stat');c.appendChild(h('div','num',a[1]));c.appendChild(h('div','lbl',a[0]));$('stats').appendChild(c);});
D.hosts.forEach(function(x){const r=h('div','hostrow');r.appendChild(h('div','',x.host+'  ('+x.count+' findings)'));const b=h('div','bar');const i=h('i');i.style.width=x.score+'%';i.style.background=x.score>75?COL.Critical:x.score>50?COL.High:x.score>25?COL.Medium:COL.Low;b.appendChild(i);r.appendChild(b);r.appendChild(h('div','',x.score+'/100'));$('hosts').appendChild(r);});
const rank={Critical:4,High:3,Medium:2,Low:1};
D.tactics.forEach(function(t){const col=h('div','col');col.appendChild(h('b','',t));const m={};
D.findings.filter(f=>f.tactic===t).forEach(function(f){const k=f.technique;if(!m[k]||rank[f.severity]>rank[m[k].sev])m[k]={sev:f.severity,n:0,name:f.name};m[k].n++;});
Object.keys(m).forEach(function(k){const a=h('a','chip '+m[k].sev,k+' x'+m[k].n);a.href='https://attack.mitre.org/techniques/'+k.replace('.','/')+'/';a.target='_blank';a.rel='noopener';a.title=m[k].name;col.appendChild(a);});
$('matrix').appendChild(col);});
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
function node(n,d){const li=h('li');const t=h('div','tn'+(n.sev?' f':''),n.label+(n.sev?'  ['+n.sev+']':'')+'   '+n.cmd.slice(0,110));if(n.sev)t.style.color=COL[n.sev];li.appendChild(t);
if(n.kids.length&&d<30){const ul=h('ul','tree');n.kids.forEach(k=>ul.appendChild(node(k,d+1)));li.appendChild(ul);}return li;}
const root=h('ul','tree root');Object.values(by).filter(n=>!n.has).forEach(n=>root.appendChild(node(n,0)));
$('tree').appendChild(root);if(!root.children.length)$('tree').textContent='No flagged process chains (Sysmon event 1 data required).';})();
(function(){const el=$('graph3d');
if(typeof THREE==='undefined'){el.appendChild(h('p','muted','3D view needs internet access to load three.js from cdnjs. All other sections work offline.'));return;}
if(!D.graph.nodes.length){el.appendChild(h('p','muted','No graph data (needs Sysmon process creation events).'));return;}
const W=el.clientWidth,H=el.clientHeight;const scene=new THREE.Scene();
const cam=new THREE.PerspectiveCamera(60,W/H,0.1,3000);cam.position.set(0,0,230);
const ren=new THREE.WebGLRenderer({antialias:true});ren.setSize(W,H);ren.setPixelRatio(Math.min(2,window.devicePixelRatio||1));el.appendChild(ren.domElement);
const world=new THREE.Group();scene.add(world);
const nodes=D.graph.nodes.map(n=>Object.assign({},n,{p:new THREE.Vector3((Math.random()-.5)*120,(Math.random()-.5)*120,(Math.random()-.5)*120),v:new THREE.Vector3()}));
const idx={};nodes.forEach((n,i)=>idx[n.id]=i);const links=D.graph.links.filter(l=>l.s in idx&&l.t in idx);
for(let it=0;it<320;it++){
for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){const d=nodes[i].p.clone().sub(nodes[j].p);const q=Math.max(d.lengthSq(),1);d.normalize().multiplyScalar(2600/q);nodes[i].v.add(d);nodes[j].v.sub(d);}
links.forEach(l=>{const a=nodes[idx[l.s]],b=nodes[idx[l.t]];const d=b.p.clone().sub(a.p);const len=d.length()||1;d.normalize().multiplyScalar((len-38)*0.03);a.v.add(d);b.v.sub(d);});
nodes.forEach(n=>{n.v.sub(n.p.clone().multiplyScalar(0.004));n.p.add(n.v);n.v.multiplyScalar(0.8);});}
const sc={Critical:0xef4444,High:0xf97316,Medium:0xeab308,Low:0x22c55e};const meshes=[];
nodes.forEach(n=>{const flagged=!!n.sev;const col=n.kind==='net'?0xa855f7:(flagged?sc[n.sev]:0x38bdf8);
const geo=n.kind==='net'?new THREE.OctahedronGeometry(6):new THREE.SphereGeometry(flagged?5.5:3.5,20,20);
const m=new THREE.Mesh(geo,new THREE.MeshBasicMaterial({color:col}));m.position.copy(n.p);m.userData=n;world.add(m);meshes.push(m);
if(flagged){const g=new THREE.Mesh(new THREE.SphereGeometry(9,16,16),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0.15}));g.position.copy(n.p);world.add(g);m.userData.glow=g;}});
const pos=[];links.forEach(l=>{const a=nodes[idx[l.s]].p,b=nodes[idx[l.t]].p;pos.push(a.x,a.y,a.z,b.x,b.y,b.z);});
const lg=new THREE.BufferGeometry();lg.setAttribute('position',new THREE.Float32BufferAttribute(pos,3));
world.add(new THREE.LineSegments(lg,new THREE.LineBasicMaterial({color:0x4b5d85})));
const sp=[];for(let i=0;i<500;i++)sp.push((Math.random()-.5)*1200,(Math.random()-.5)*1200,(Math.random()-.5)*1200);
const sg=new THREE.BufferGeometry();sg.setAttribute('position',new THREE.Float32BufferAttribute(sp,3));scene.add(new THREE.Points(sg,new THREE.PointsMaterial({color:0x3b4a6b,size:1.6})));
let drag=false,lx=0,ly=0,auto=true;const ray=new THREE.Raycaster(),mv=new THREE.Vector2(),tip=$('tip');
el.addEventListener('mousedown',e=>{drag=true;auto=false;lx=e.clientX;ly=e.clientY;el.style.cursor='grabbing';});
window.addEventListener('mouseup',()=>{drag=false;el.style.cursor='grab';});
el.addEventListener('mousemove',e=>{const r=el.getBoundingClientRect();
if(drag){world.rotation.y+=(e.clientX-lx)*0.006;world.rotation.x+=(e.clientY-ly)*0.006;lx=e.clientX;ly=e.clientY;}
mv.x=((e.clientX-r.left)/r.width)*2-1;mv.y=-((e.clientY-r.top)/r.height)*2+1;ray.setFromCamera(mv,cam);const hit=ray.intersectObjects(meshes)[0];
if(hit){const n=hit.object.userData;tip.style.display='block';tip.style.left=Math.min(e.clientX-r.left+14,r.width-300)+'px';tip.style.top=(e.clientY-r.top+14)+'px';tip.textContent=n.label+(n.sev?'  ['+n.sev+']':'')+'\n'+(n.host||'')+'\n'+(n.cmd||'');tip.style.whiteSpace='pre-wrap';}else tip.style.display='none';});
el.addEventListener('wheel',e=>{e.preventDefault();cam.position.z=Math.max(60,Math.min(600,cam.position.z+e.deltaY*0.2));},{passive:false});
el.addEventListener('dblclick',()=>{auto=!auto;});
window.addEventListener('resize',()=>{const w=el.clientWidth;ren.setSize(w,el.clientHeight);cam.aspect=w/el.clientHeight;cam.updateProjectionMatrix();});
let t=0;(function loop(){requestAnimationFrame(loop);t+=0.03;if(auto)world.rotation.y+=0.0025;
meshes.forEach(m=>{if(m.userData.glow){const s=1+0.25*Math.sin(t+m.position.x);m.userData.glow.scale.set(s,s,s);}});ren.render(scene,cam);})();
})();
</script></body></html>
"""