const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
function harness(){
 const els=new Map();
 function el(){return {textContent:'',hidden:false,value:'',style:{},dataset:{},children:[],addEventListener(){},setAttribute(){},append(...items){this.children.push(...items)},replaceChildren(){this.children=[]},classList:{add(){},remove(){}}};}
 const context=vm.createContext({location:{hash:'#overview'},window:{scrollTo(){},addEventListener(){}},document:{getElementById(id){if(!els.has(id))els.set(id,el());return els.get(id)},createElement:el,querySelector:el,querySelectorAll(){return []}},URL,Blob,setTimeout,fetch:()=>new Promise(()=>{})});
 vm.runInContext(fs.readFileSync(path.join(root,'dist/app.js'),'utf8'),context);
 context.data=JSON.parse(fs.readFileSync(path.join(root,'dist/demo.json'),'utf8'));
 return {context,els,run:code=>vm.runInContext(code,context)};
}
test('real generated report renders all controls and computes metrics',()=>{const h=harness();h.run('applyReport(data,"demo",true)');assert.equal(h.els.get('total').textContent,18);assert.equal(h.els.get('failed').textContent,3);assert.equal(h.els.get('uncertain').textContent,4);assert.equal(h.els.get('score').textContent,'%79');assert.equal(h.els.get('findings').children.length,18);});
test('status, severity and search filters combine',()=>{const h=harness();h.run('applyReport(data,"demo",true); statusFilter="FAIL"; render()');assert.equal(h.els.get('findings').children.length,3);h.els.get('search').value='nonexistent';h.run('render()');assert.match(h.els.get('visible-count').textContent,/^0 \/ 18/);h.els.get('search').value='';h.els.get('severity').value='low';h.run('render()');assert.match(h.els.get('visible-count').textContent,/^0 \/ 18/);});
test('empty report has no compliance score',()=>{const h=harness();h.run('data.findings=[]; applyReport(data,"empty",false)');assert.equal(h.els.get('score').textContent,'—');assert.match(h.els.get('findings').children[0].textContent,/güvenli olduğu anlamına gelmez/);});
test('invalid data is rejected without replacing the current report',()=>{const h=harness();h.run('applyReport(data,"demo",true)');for(const mutation of ['data.schema_version=2','data.findings[0].status="OK"','data.findings[0].evidence=[null]']){assert.throws(()=>h.run(mutation+'; applyReport(data,"bad",false)'));}assert.equal(h.els.get('report-name').textContent,'Örnek yapılandırma');});
test('untrusted text remains literal and script links are omitted',()=>{const h=harness();h.run('data.findings[0].title="<img src=x onerror=alert(1)>";data.findings[0].reference="javascript:alert(1)";applyReport(data,"demo",false)');const item=h.els.get('findings').children[0];assert.equal(item.children[0].children[0].children[1].textContent,'<img src=x onerror=alert(1)>');assert.equal(item.children[1].children.length,5);});

test('dashboard counts and category bars come from the current report',()=>{const h=harness();h.run('applyReport(data,"demo",true)');assert.equal(h.els.get('passed').textContent,11);assert.equal(h.els.get('priority-count').textContent,3);assert.equal(h.els.get('priorities').children.length,3);assert.equal(h.els.get('module-count').textContent,new Set(h.context.data.findings.map(f=>f.category)).size+' MODÜL');});
test('category filter excludes other modules',()=>{const h=harness();h.run('applyReport(data,"demo",true)');h.els.get('category').value='ssh';h.run('render()');assert.equal(h.els.get('findings').children.length,4);});
test('report history stays bounded and reviewing does not add duplicates',()=>{const h=harness();h.run('for(let i=0;i<12;i++)applyReport(data,"report "+i,false);');assert.equal(h.els.get('report-list').children.length,10);h.run('applyReport(data,"review",false,false)');assert.equal(h.els.get('report-list').children.length,10);});
test('navigation selects the requested page and hides unrelated results',()=>{const h=harness();h.run('location.hash="#reports";navigate()');assert.equal(h.els.get('page-title').textContent,'Her inceleme, bir adım ileri');assert.equal(h.els.get('findings-section').hidden,true);h.run('location.hash="#findings";navigate()');assert.equal(h.els.get('findings-section').hidden,false);});
