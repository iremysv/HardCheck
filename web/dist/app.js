'use strict';
const $ = id => document.getElementById(id);
const statuses = ['PASS','FAIL','WARN','SKIP','ERROR'];
const severities = ['low','medium','high','critical'];
const labels = {PASS:'Uygun',FAIL:'Müdahale gerekli',WARN:'Belirsiz',SKIP:'Atlandı',ERROR:'Hata'};
const severityLabels = {low:'Düşük',medium:'Orta',high:'Yüksek',critical:'Kritik'};
const evidenceLabels = {assessment:'Değerlendirme',setting:'Ayar',records_inspected:'İncelenen kayıt',noncompliant_records:'Uygunsuz kayıt',coverage:'Kapsam',owner_uid:'Sahip UID',mode_bits:'İzin bitleri',sticky_bit:'Sticky bit',entries_inspected:'İncelenen öğe',ipv4:'IPv4',ipv6:'IPv6',tcp_21_listeners:'TCP 21 dinleyicisi',tcp_23_listeners:'TCP 23 dinleyicisi',backend:'Kaynak',legacy_package:'Eski paket',legacy_unit:'Eski servis',positive_credits:'Pozitif krediler',enforcing:'Zorunlu uygulama'};
const valueLabels = {unknown:'Bilinmiyor',no:'Hayır',yes:'Evet',invalid:'Geçersiz',complete_within_scope:'Kapsam içinde tam',partial:'Kısmi',present:'Var',absent:'Yok'};
let report=null, statusFilter='ALL', sequence=0;
let reportHistory=[], activePage='overview', demoData=null;
const categoryLabels={ssh:'SSH',users:'Hesaplar',filesystem:'Dosya sistemi',network:'Ağ',kernel:'Çekirdek',services:'Servisler'};
function node(tag, text, cls){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
function validateReport(data){
 if(!data || data.schema_version!==1 || !Array.isArray(data.findings) || data.findings.length>1000 || !data.scope || !Number.isInteger(data.scope.collected_controls) || data.scope.collected_controls<data.findings.length)throw new Error('HardCheck şema sürümü 1 ile oluşturulmuş bir JSON raporu seç.');
 const ids=new Set();
 for(const f of data.findings){
  if(!f || !statuses.includes(f.status) || !severities.includes(f.severity) || !['check_id','title','category','expected','rationale','remediation','note','reference'].every(k=>typeof f[k]==='string' && f[k].length<=50000) || !f.check_id || ids.has(f.check_id) || !Array.isArray(f.evidence) || f.evidence.length>100 || !f.evidence.every(e=>e && typeof e.key==='string' && e.key.length<=100 && (typeof e.value==='string' && e.value.length<=1000 || typeof e.value==='number' && Number.isFinite(e.value))))throw new Error('Raporun bulgu alanları eksik veya geçersiz. Dosyayı HardCheck ile yeniden oluştur.');
  ids.add(f.check_id);
 }
 return data;
}
function message(text){$('message').textContent=text;$('message').hidden=!text;}
function applyReport(data,name,demo,remember=true){
 report=validateReport(data);statusFilter='ALL';$('search').value='';$('severity').value='ALL';$('category').value='ALL';
 $('source-tag').textContent=demo?'ÖRNEK RAPOR':'YÜKLENEN RAPOR';$('report-name').textContent=demo?'Örnek yapılandırma':name;
 $('report-caption').textContent=demo?'Arayüzü keşfetmen için hazırlanmış temsili sonuçlar. Gerçek bir sistem taraması değildir.':'Dosya yalnızca bu tarayıcı oturumunda açık. Kaynak: HardCheck '+String(data.hardcheck_version || '—')+' · Rapor dili: '+(data.language==='tr'?'Türkçe':data.language==='en'?'İngilizce':'Belirtilmemiş');
 const counts=Object.fromEntries(statuses.map(s=>[s,data.findings.filter(f=>f.status===s).length]));
 const total=data.findings.length, assessed=counts.PASS+counts.FAIL;
 const score=assessed?Math.round(counts.PASS/assessed*100):null;
 $('total').textContent=total;$('failed').textContent=counts.FAIL;$('uncertain').textContent=total-assessed;
 $('coverage').textContent=assessed+'/'+total+' kesin değerlendirildi'+(data.scope.collected_controls>total?' · '+(data.scope.collected_controls-total)+' kaynakta filtrelendi':'');
 $('score').textContent=score===null?'—':'%'+score;$('score-bar').style.width=(score || 0)+'%';message('');
 if(remember){reportHistory.unshift({data,name:name || 'Örnek yapılandırma',demo,opened:new Date().toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'})});reportHistory=reportHistory.slice(0,10);}
 updateDashboard(counts,score);render();renderHistory();
}
function addSection(parent,title,text,wide=false){const section=node('div',undefined,wide?'detail-wide':'');section.append(node('h3',title),node('p',text || 'Belirtilmemiş'));parent.append(section);}
function render(){
 if(!report)return;
 document.querySelectorAll('[data-status]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.status===statusFilter)));
 const query=$('search').value.toLocaleLowerCase('tr').trim(), severity=$('severity').value, category=$('category').value;
 const filtered=report.findings.filter(f=>(statusFilter==='ALL'||(statusFilter==='UNCERTAIN'?['WARN','SKIP','ERROR'].includes(f.status):f.status===statusFilter)) && (category==='ALL'||f.category===category) && (severity==='ALL'||f.severity===severity) && (!query||[f.check_id,f.title,f.category].join(' ').toLocaleLowerCase('tr').includes(query)));
 $('findings').replaceChildren();$('count').textContent=report.findings.length;$('visible-count').textContent=filtered.length+' / '+report.findings.length+' bulgu gösteriliyor';
 if(!filtered.length){$('findings').append(node('p',report.findings.length?'Bu filtrelerle eşleşen bulgu yok. Aramayı veya filtreleri değiştir.':'Bu raporda gösterilen bulgu yok. Bu, sistemin güvenli olduğu anlamına gelmez.','empty'));return;}
 for(const f of filtered){
  const details=node('details'), summary=node('summary'), label=node('span',undefined,'finding-label');
  label.append(node('span',f.check_id,'check-id'),node('span',f.title,'finding-title'));
  summary.append(label,node('span',severityLabels[f.severity],'severity'),node('span',f.status,'badge '+f.status),node('span','›','chevron'));
  const content=node('div',undefined,'detail-content');
  addSection(content,'Beklenen',f.expected);addSection(content,'Gözlem / kanıt',f.evidence.map(e=>(evidenceLabels[e.key]||e.key)+': '+(valueLabels[e.value]||String(e.value))).join('\n'));
  addSection(content,'Neden önemli?',f.rationale);addSection(content,'Önerilen adım',f.remediation);addSection(content,'Değerlendirme notu',f.note,true);
  try{const url=new URL(f.reference);if(['https:','http:'].includes(url.protocol)){const a=node('a','Kaynağı incele ↗');a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';content.append(a);}}catch{}
  details.append(summary,content);$('findings').append(details);
 }
}
async function loadDemo(){const current=++sequence;try{const response=await fetch('demo.json');if(!response.ok)throw new Error();const data=await response.json();if(current===sequence){demoData=data;applyReport(data,'',true);}}catch{if(current===sequence)message('Örnek rapor açılamadı. Kendi JSON raporunu yükleyebilirsin.');}}
async function loadFile(file){if(!file)return;const current=++sequence;try{if(file.size>5*1024*1024)throw new Error('Dosya 5 MB sınırını aşıyor. Daha küçük bir rapor seç.');let data;try{data=JSON.parse(await file.text());}catch{throw new Error('Dosya geçerli JSON içermiyor. HardCheck JSON raporunu seç.');}if(current===sequence)applyReport(data,file.name,false);}catch(error){if(current===sequence)message(error.message);}finally{$('file').value='';}}
$('upload').addEventListener('click',()=>$('file').click());$('file').addEventListener('change',e=>loadFile(e.target.files[0]));
$('reset').addEventListener('click',loadDemo);$('search').addEventListener('input',render);$('severity').addEventListener('change',render);$('category').addEventListener('change',render);
for(const button of document.querySelectorAll('[data-status]'))button.addEventListener('click',()=>{statusFilter=button.dataset.status;render();});
$('help').addEventListener('click',()=>{location.hash='guide';});for(const id of ['close-help','understood'])$(id).addEventListener('click',()=>$('help-dialog').close());
$('download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json'}));const a=node('a');a.href=url;a.download=$('source-tag').textContent==='ÖRNEK RAPOR'?'hardcheck-ornek.json':'hardcheck-rapor.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});

function updateDashboard(counts,score){
 $('passed').textContent=counts.PASS;
 $('nav-count').textContent=counts.FAIL+counts.WARN+counts.ERROR;
 $('gauge').style.background=`conic-gradient(from 200deg,var(--accent) ${(score||0)*3.6}deg,#24333d 0)`;
 $('score-state').textContent=score===null?'Kesin değerlendirme yok':counts.FAIL?'● İyileştirme gerekli':counts.WARN+counts.SKIP+counts.ERROR?'● Eksik değerlendirmeler var':'✓ Gösterilen kontroller uygun';
 $('priority-count').textContent=counts.FAIL;
 const groups=[...new Set(report.findings.map(f=>f.category))];
 $('module-count').textContent=groups.length+' MODÜL';
 $('category').replaceChildren();const all=node('option','Tüm alanlar');all.value='ALL';$('category').append(all);$('category').value='ALL';
 $('categories').replaceChildren();
 for(const category of groups){
  const option=node('option',categoryLabels[category]||category);option.value=category;$('category').append(option);
  const items=report.findings.filter(f=>f.category===category), passed=items.filter(f=>f.status==='PASS').length;
  const row=node('div',undefined,'category-row'),bar=node('div',undefined,'category-bar');
  for(const status of statuses){const count=items.filter(f=>f.status===status).length;if(count){const segment=node('i',undefined,status);segment.style.width=(count/items.length*100)+'%';segment.title=status+': '+count;bar.append(segment);}}
  row.append(node('span',categoryLabels[category]||category),bar,node('small',passed+'/'+items.length));$('categories').append(row);
 }
 if(!groups.length)$('categories').append(node('p','Bu raporda gösterilen kontrol alanı yok.','empty'));
 $('priorities').replaceChildren();
 const priority=report.findings.filter(f=>f.status==='FAIL').sort((a,b)=>severities.indexOf(b.severity)-severities.indexOf(a.severity));
 for(const f of priority.slice(0,5)){
  const button=node('button',undefined,'priority-row'),text=node('span');
  text.append(node('strong',f.title),node('small',f.check_id+' · '+(categoryLabels[f.category]||f.category)));
  button.append(node('span','△','priority-icon'),text,node('span',severityLabels[f.severity]+' →'));
  button.addEventListener('click',()=>{statusFilter='ALL';$('category').value='ALL';$('severity').value='ALL';$('search').value=f.check_id;render();location.hash='findings';const first=$('findings').querySelector('details');if(first)first.open=true;});$('priorities').append(button);
 }
 if(!priority.length)$('priorities').append(node('p','Gösterilen kontrollerde FAIL yok. Belirsiz ve atlanan sonuçları da inceleyin.','empty'));
}
function downloadData(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)+'\n'],{type:'application/json'}));const a=node('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function renderHistory(){
 $('report-list').replaceChildren();
 for(const entry of reportHistory){
  const row=node('article',undefined,'panel report-item'),info=node('div',undefined,'report-info');
  const passed=entry.data.findings.filter(f=>f.status==='PASS').length,failed=entry.data.findings.filter(f=>f.status==='FAIL').length;
  info.append(node('strong',entry.name+(entry.demo?' · ÖRNEK':'')),node('p','Açılış '+entry.opened+' · '+entry.data.findings.length+' kontrol · '+failed+' başarısız'));
  const inspect=node('button','İncele','button secondary');inspect.addEventListener('click',()=>{applyReport(entry.data,entry.name,entry.demo,false);location.hash='overview';});
  const download=node('button','↓','icon-button');download.setAttribute('aria-label',entry.name+' JSON indir');download.addEventListener('click',()=>downloadData(entry.data,entry.demo?'hardcheck-ornek.json':'hardcheck-rapor.json'));
  row.append(node('span','▤','report-icon'),info,node('span',passed+failed?'%'+Math.round(passed/(passed+failed)*100):'—','report-score'),inspect,download);$('report-list').append(row);
 }
}
const pages={overview:['Genel bakış','Güvenliğe genel bakış','Sisteminizi tanıyın. Riskleri görün. Kanıtla ilerleyin.'],findings:['Bulgular','Her bulgunun arkasında bir kanıt','Sonuçları daraltın. Beklenen koşulu ve önerilen adımları inceleyin.'],reports:['Raporlar','Her inceleme, bir adım ileri','Bu oturumda açtığınız raporları inceleyin ve yanınızda taşıyın.'],guide:['Nasıl çalışır?','Güvenliğe giden kısa yol','HardCheck panelini üç adımda keşfedin.']};
function navigate(){
 activePage=Object.hasOwn(pages,location.hash.slice(1))?location.hash.slice(1):'overview';
 const [label,title,description]=pages[activePage];$('breadcrumb').textContent=label;$('page-title').textContent=title;$('page-description').textContent=description;document.title='HardCheck · '+label;
 document.querySelectorAll('[data-page]').forEach(el=>el.hidden=el.dataset.page!==activePage);
 document.querySelectorAll('[data-nav]').forEach(el=>{el.classList.toggle('active',el.dataset.nav===activePage);if(el.dataset.nav===activePage)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
 $('findings-section').hidden=!['overview','findings'].includes(activePage);window.scrollTo({top:0,behavior:'instant'});
}
async function showScan(){
 try{if(!demoData){const response=await fetch('demo.json');if(!response.ok)throw new Error();demoData=validateReport(await response.json());}
 $('scan-categories').replaceChildren();for(const category of [...new Set(demoData.findings.map(f=>f.category))]){const label=node('label'),input=node('input');input.type='checkbox';input.name='category';input.value=category;input.checked=true;label.append(input,node('span',categoryLabels[category]||category));$('scan-categories').append(label);}
 $('scan-error').textContent='';$('scan-dialog').showModal();}catch{message('Örnek rapor yüklenemedi. Lütfen yeniden deneyin.');}
}
$('new-scan').addEventListener('click',showScan);$('guide-demo').addEventListener('click',showScan);$('close-scan').addEventListener('click',()=>$('scan-dialog').close());
$('scan-form').addEventListener('submit',e=>{e.preventDefault();const selected=[...$('scan-categories').querySelectorAll('input:checked')].map(input=>input.value);if(!selected.length){$('scan-error').textContent='En az bir kontrol alanı seçin.';return;}
 ++sequence;const data=JSON.parse(JSON.stringify(demoData));data.findings=data.findings.filter(f=>selected.includes(f.category));data.scope.collected_controls=data.findings.length;data.scope.hidden_controls=0;
 // Recompute exported summaries for this synthetic subset, keeping CLI schema.
 const counts=Object.fromEntries(statuses.map(s=>[s,data.findings.filter(f=>f.status===s).length]));const assessed=counts.PASS+counts.FAIL;
 const summary={total:data.findings.length,assessed,counts,score_percent:assessed?Math.round(counts.PASS/assessed*10000)/100:null,coverage_percent:data.findings.length?Math.round(assessed/data.findings.length*10000)/100:null};data.summary=summary;data.scan_summary={...summary};
 applyReport(data,'Örnek yapılandırma',true);$('scan-dialog').close();location.hash='overview';
});
$('guide-download').addEventListener('click',async()=>{try{if(!demoData){const response=await fetch('demo.json');if(!response.ok)throw new Error();demoData=validateReport(await response.json());}downloadData(demoData,'hardcheck-ornek.json');}catch{message('Örnek rapor indirilemedi.');}});
window.addEventListener('hashchange',navigate);navigate();loadDemo();
