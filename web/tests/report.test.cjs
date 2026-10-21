const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
function harness(){
 const els=new Map();
 function el(){return {textContent:'',hidden:false,value:'',style:{},dataset:{},children:[],listeners:{},addEventListener(name,handler){this.listeners[name]=handler},setAttribute(){},append(...items){this.children.push(...items)},replaceChildren(...items){this.children=items},classList:{add(){},remove(){}}};}
 const context=vm.createContext({location:{hash:'#overview'},window:{scrollTo(){},addEventListener(){}},document:{getElementById(id){if(!els.has(id))els.set(id,el());return els.get(id)},createElement:el,querySelector(selector){return selector.startsWith("meta[")?null:el()},querySelectorAll(){return []}},URL,Blob,setTimeout,fetch:()=>new Promise(()=>{})});
 vm.runInContext(fs.readFileSync(path.join(root,'dist/app.js'),'utf8'),context);
 context.data=JSON.parse(fs.readFileSync(path.join(root,'dist/demo.json'),'utf8'));
 return {context,els,run:code=>vm.runInContext(code,context)};
}
test('real generated report renders all controls and computes metrics',()=>{const h=harness();h.run('applyReport(data,"demo",true)');assert.equal(h.els.get('total').textContent,18);assert.equal(h.els.get('failed').textContent,3);assert.equal(h.els.get('warned').textContent,h.context.data.findings.filter(f=>f.status==='WARN').length);assert.equal(h.els.get('score').textContent,'%79');assert.equal(h.els.get('findings').children.length,10);});
test('status, severity and search filters combine',()=>{const h=harness();h.run('applyReport(data,"demo",true); statusFilter="FAIL"; render()');assert.equal(h.els.get('findings').children.length,3);h.els.get('search').value='nonexistent';h.run('render()');assert.match(h.els.get('visible-count').textContent,/^0 \/ 18/);h.els.get('search').value='';h.els.get('severity').value='low';h.run('render()');assert.match(h.els.get('visible-count').textContent,/^0 \/ 18/);});
test('empty report has no compliance score',()=>{const h=harness();h.run('data.findings=[]; applyReport(data,"empty",false)');assert.equal(h.els.get('score').textContent,'—');assert.match(h.els.get('findings').children[0].textContent,/güvenli olduğu anlamına gelmez/);});
test('invalid data is rejected without replacing the current report',()=>{const h=harness();h.run('applyReport(data,"demo",true)');for(const mutation of ['data.schema_version=2','data.findings[0].status="OK"','data.findings[0].evidence=[null]']){assert.throws(()=>h.run(mutation+'; applyReport(data,"bad",false)'));}assert.equal(h.els.get('report-name').textContent,'Örnek yapılandırma');});
test('untrusted text remains literal and script links are omitted',()=>{const h=harness();h.run('data.findings[0].title="<img src=x onerror=alert(1)>";data.findings[0].reference="javascript:alert(1)";applyReport(data,"demo",false);$("sort").value="id";render()');const item=h.els.get('findings').children[0];assert.equal(item.children[0].children[0].children[1].textContent,'<img src=x onerror=alert(1)>');assert.equal(item.children[1].children.length,5);});

test('dashboard counts and category bars come from the current report',()=>{const h=harness();h.run('applyReport(data,"demo",true)');assert.equal(h.els.get('passed').textContent,11);assert.equal(h.els.get('priority-count').textContent,3);assert.equal(h.els.get('priorities').children.length,3);assert.equal(h.els.get('module-count').textContent,new Set(h.context.data.findings.map(f=>f.category)).size+' MODÜL');});
test('category filter excludes other modules',()=>{const h=harness();h.run('applyReport(data,"demo",true)');h.els.get('category').value='ssh';h.run('render()');assert.equal(h.els.get('findings').children.length,4);});
test('report history stays bounded and reviewing does not add duplicates',()=>{const h=harness();h.run('for(let i=0;i<12;i++)applyReport(data,"report "+i,false);');assert.equal(h.els.get('report-list').children.length,10);h.run('applyReport(data,"review",false,false)');assert.equal(h.els.get('report-list').children.length,10);});
test('navigation selects the requested page and hides unrelated results',()=>{const h=harness();h.run('location.hash="#reports";navigate()');assert.equal(h.els.get('page-title').textContent,'Her inceleme, bir adım ileri');assert.equal(h.els.get('findings-section').hidden,true);h.run('location.hash="#findings";navigate()');assert.equal(h.els.get('findings-section').hidden,false);});

test('pagination covers all findings without duplication',()=>{const h=harness();h.run('applyReport(data,"demo",true)');const first=h.els.get('findings').children.map(el=>el.children[0].children[0].children[0].textContent);h.els.get('next-page').listeners.click();const second=h.els.get('findings').children.map(el=>el.children[0].children[0].children[0].textContent);assert.equal(first.length,10);assert.equal(second.length,8);assert.equal(new Set([...first,...second]).size,18);assert.equal(h.els.get('next-page').disabled,true);h.els.get('search').value='SSH';h.run('render()');assert.equal(h.els.get('page-number').textContent,'1 / 1');assert.equal(h.els.get('findings').children.length,4);});
test('clear filters restores all matches',()=>{const h=harness();h.run('applyReport(data,"demo",true);statusFilter="FAIL";$("search").value="missing";render();clearFilters()');assert.match(h.els.get('visible-count').textContent,/^18 \/ 18/);assert.equal(h.els.get('clear-filters').disabled,true);});
test('priority sort ranks errors and critical failures before passing controls',()=>{const h=harness();const actual=h.run('[{check_id:"A",title:"A",status:"PASS",severity:"critical"},{check_id:"B",title:"B",status:"FAIL",severity:"low"},{check_id:"C",title:"C",status:"FAIL",severity:"critical"},{check_id:"D",title:"D",status:"ERROR",severity:"low"}].sort(compareFindings("priority")).map(f=>f.check_id).join(",")');assert.equal(actual,'D,C,B,A');});
test('comparison does not treat missing or uncertain findings as remediation',()=>{const h=harness();const actual=h.run('compareReports({findings:[{check_id:"A",status:"FAIL"},{check_id:"B",status:"FAIL"},{check_id:"C",status:"FAIL"},{check_id:"D",status:"PASS"}]},{findings:[{check_id:"A",status:"PASS"},{check_id:"C",status:"WARN"},{check_id:"D",status:"FAIL"},{check_id:"E",status:"PASS"}]}).map(r=>r.kind).join(",")');assert.equal(actual,'resolved,removed,changed,regressed,added');});
test('comparison requires distinct reports and renders actual transitions',()=>{const h=harness();h.run('applyReport(data,"before",false); const newer=JSON.parse(JSON.stringify(data));newer.findings[0].status="PASS";applyReport(newer,"after",false);showComparison()');assert.equal(h.els.get('comparison-result').children[0].children[0].children[0].textContent,1);h.els.get('compare-before').value='0';h.run('showComparison()');assert.match(h.els.get('comparison-result').children[0].textContent,/İki farklı/);});
test('filtered internal errors remain explicit outside the score',()=>{const h=harness();h.run('data.scope.collected_controls=20;data.scan_summary.counts.ERROR=2;applyReport(data,"filtered",false)');assert.match(h.els.get('scope-notice').textContent,/2 kontrol kaynak raporda/);assert.match(h.els.get('scope-notice').textContent,/2 ERROR sonucu kaynak raporda gizli/);assert.equal(h.els.get('scope-notice').hidden,false);});

test('evidence uses the Python JSON contract and retains unknown observations',()=>{
 const {execFileSync}=require('node:child_process');
 const python=process.env.HARDCHECK_TEST_PYTHON || path.join(root,'../.venv/bin/python');
 const code=`import json, tempfile
from pathlib import Path
from hardcheck.checks.listeners import LegacyListenerCheck
from hardcheck.reporting import json_report
with tempfile.TemporaryDirectory() as directory:
 root = Path(directory)
 for name in ('tcp', 'tcp6'):
  (root / name).write_text('sl local_address rem_address st tx_queue rx_queue\\n')
 result = LegacyListenerCheck(root).run()
 print(json_report([result], [result], language='tr'))
`;
 const h=harness();h.context.actual=JSON.parse(execFileSync(python,['-c',code],{encoding:'utf8',env:{...process.env,PYTHONPATH:path.join(root,'../src')}}));
 h.run('applyReport(actual,"fixture",false)');
 const text=h.els.get('findings').children[0].children[1].children[1].children[1].textContent;
 assert.equal(text,'TCP 21 dinleyicisi: 0\nTCP 23 dinleyicisi: 0\nKapsam: Kapsam içinde tam');
 assert.equal(h.run('formatEvidence({key:"mode_bits",value:420})'),'İzin bitleri: 0644');
 assert.equal(h.run('formatEvidence({key:"assessment",value:"unknown"})'),'Değerlendirme: Bilinmiyor');
 assert.equal(h.context.actual.findings[0].status,'PASS');
});


test('separate outcome counts and score coverage reflect the report, not fixtures',()=>{
 const h=harness();h.run('data.findings=data.findings.slice(0,5);data.findings.forEach((f,i)=>f.status=statuses[i]);applyReport(data,"synthetic",false)');
 for(const id of ['passed','failed','warned','skipped','errors'])assert.equal(h.els.get(id).textContent,1);
 assert.equal(h.els.get('score').textContent,'%50');
 assert.equal(h.els.get('score-coverage').textContent,'2/5 kontrol kesin değerlendirildi · %40 kapsam');
 h.run('data.findings.forEach(f=>f.status="SKIP");applyReport(data,"unassessed",false)');
 assert.equal(h.els.get('score').textContent,'—');
 assert.equal(h.els.get('skipped').textContent,5);
 assert.equal(h.els.get('score-coverage').textContent,'0/5 kontrol kesin değerlendirildi · %0 kapsam');
});

test('history distinguishes local results from uploaded reports',()=>{
 const h=harness();h.run('applyReport(data,"local fixture",false,true,"local")');
 assert.equal(h.els.get('source-tag').textContent,'YEREL TARAMA');
 h.els.get('report-list').children[0].children[3].listeners.click();
 assert.equal(h.els.get('source-tag').textContent,'ÖNCEKİ TARAMA');
 h.run('applyReport(data,"uploaded fixture",false)');
 assert.equal(h.els.get('source-tag').textContent,'YÜKLENEN RAPOR');
});

test('overlapping local status refreshes remember a completed scan only once',async()=>{
 const h=harness();let waiting=[];
 h.context.document.querySelector=()=>({content:'synthetic-token'});
 h.context.setTimeout=()=>{};
 h.context.fetch=async path=>{
  if(path==='/api/report.json')await new Promise(resolve=>{waiting.push(resolve);if(waiting.length===2)waiting.forEach(done=>done());});
  return {ok:true,json:async()=>path==='/api/report.json'?h.context.data:{state:'completed',generation:1,supported:true,error:null}};
 };
 h.run('$("real-scan").disabled=false');
 vm.runInContext(fs.readFileSync(path.join(root,'dist/local.js'),'utf8'),h.context);
 await h.els.get('real-scan').listeners.click();
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(waiting.length,2);
 assert.equal(h.els.get('report-list').children.length,1);
 assert.equal(h.els.get('new-scan').hidden,true);
 assert.equal(h.els.get('source-tag').textContent,'YEREL TARAMA');
});

test('malformed metadata is rejected before changing report or history',()=>{
 for(const mutation of ['bad.hardcheck_version={toString:null}','bad.language=[]','bad.scope.collected_controls=1e30']){
  const h=harness();h.run('applyReport(data,"original",false);const original=report;const bad=JSON.parse(JSON.stringify(data));');
  assert.throws(()=>h.run(mutation+';applyReport(bad,"invalid",false)'));
  assert.equal(h.run('report===original'),true);
  assert.equal(h.els.get('report-name').textContent,'original');
  assert.equal(h.run('reportHistory.length'),1);
 }
});
test('category names cannot resolve inherited object properties',()=>{
 const h=harness();
 h.run('data.findings.forEach(f=>f.category="__proto__");applyReport(data,"custom",false)');
 assert.equal(h.els.get('categories').children[0].children[0].textContent,'__proto__');
});
