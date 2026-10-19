'use strict';
const $ = id => document.getElementById(id);
const statuses = ['PASS','FAIL','WARN','SKIP','ERROR'];
const severities = ['low','medium','high','critical'];
const labels = {PASS:'Uygun',FAIL:'Müdahale gerekli',WARN:'Belirsiz',SKIP:'Atlandı',ERROR:'Hata'};
const severityLabels = {low:'Düşük',medium:'Orta',high:'Yüksek',critical:'Kritik'};
const evidenceLabels = {assessment:'Değerlendirme',setting:'Ayar',records_inspected:'İncelenen kayıt',noncompliant_records:'Uygunsuz kayıt',coverage:'Kapsam',owner_uid:'Sahip UID',mode_bits:'İzin bitleri',sticky_bit:'Sticky bit',entries_inspected:'İncelenen öğe',ipv4:'IPv4',ipv6:'IPv6',tcp_21_listeners:'TCP 21 dinleyicisi',tcp_23_listeners:'TCP 23 dinleyicisi',backend:'Kaynak',legacy_package:'Eski paket',legacy_unit:'Eski servis',positive_credits:'Pozitif krediler',enforcing:'Zorunlu uygulama'};
const valueLabels = {unknown:'Bilinmiyor',no:'Hayır',yes:'Evet',invalid:'Geçersiz',complete_within_scope:'Kapsam içinde tam',partial:'Kısmi',present:'Var',absent:'Yok'};
let report=null, statusFilter='ALL', sequence=0;
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
function applyReport(data,name,demo){
 report=validateReport(data);statusFilter='ALL';$('search').value='';$('severity').value='ALL';
 $('source-tag').textContent=demo?'ÖRNEK RAPOR':'YÜKLENEN RAPOR';$('report-name').textContent=demo?'Örnek yapılandırma':name;
 $('report-caption').textContent=demo?'Arayüzü keşfetmen için hazırlanmış temsili sonuçlar. Gerçek bir sistem taraması değildir.':'Dosya yalnızca bu tarayıcı oturumunda açık. Kaynak: HardCheck '+String(data.hardcheck_version || '—')+' · Rapor dili: '+(data.language==='tr'?'Türkçe':data.language==='en'?'İngilizce':'Belirtilmemiş');
 const counts=Object.fromEntries(statuses.map(s=>[s,data.findings.filter(f=>f.status===s).length]));
 const total=data.findings.length, assessed=counts.PASS+counts.FAIL;
 const score=assessed?Math.round(counts.PASS/assessed*100):null;
 $('total').textContent=total;$('failed').textContent=counts.FAIL;$('uncertain').textContent=total-assessed;
 $('coverage').textContent=assessed+'/'+total+' kesin değerlendirildi'+(data.scope.collected_controls>total?' · '+(data.scope.collected_controls-total)+' kaynakta filtrelendi':'');
 $('score').textContent=score===null?'—':'%'+score;$('score-bar').style.width=(score || 0)+'%';message('');render();
}
function addSection(parent,title,text,wide=false){const section=node('div',undefined,wide?'detail-wide':'');section.append(node('h3',title),node('p',text || 'Belirtilmemiş'));parent.append(section);}
function render(){
 if(!report)return;
 document.querySelectorAll('[data-status]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.status===statusFilter)));
 const query=$('search').value.toLocaleLowerCase('tr').trim(), severity=$('severity').value;
 const filtered=report.findings.filter(f=>(statusFilter==='ALL'||(statusFilter==='UNCERTAIN'?['WARN','SKIP','ERROR'].includes(f.status):f.status===statusFilter)) && (severity==='ALL'||f.severity===severity) && (!query||[f.check_id,f.title,f.category].join(' ').toLocaleLowerCase('tr').includes(query)));
 $('findings').replaceChildren();$('count').textContent=report.findings.length;$('visible-count').textContent=filtered.length+' / '+report.findings.length+' bulgu gösteriliyor';
 if(!filtered.length){$('findings').append(node('p',report.findings.length?'Bu filtrelerle eşleşen bulgu yok. Aramayı veya filtreleri değiştir.':'Bu raporda gösterilen bulgu yok. Bu, sistemin güvenli olduğu anlamına gelmez.','empty'));return;}
 for(const f of filtered){
  const details=node('details'), summary=node('summary'), label=node('span',undefined,'finding-label');
  label.append(node('span',f.check_id,'check-id'),node('span',f.title,'finding-title'));
  summary.append(label,node('span',severityLabels[f.severity],'severity'),node('span',labels[f.status],'badge '+f.status),node('span','›','chevron'));
  const content=node('div',undefined,'detail-content');
  addSection(content,'Beklenen',f.expected);addSection(content,'Gözlem / kanıt',f.evidence.map(e=>(evidenceLabels[e.key]||e.key)+': '+(valueLabels[e.value]||String(e.value))).join('\n'));
  addSection(content,'Neden önemli?',f.rationale);addSection(content,'Önerilen adım',f.remediation);addSection(content,'Değerlendirme notu',f.note,true);
  try{const url=new URL(f.reference);if(['https:','http:'].includes(url.protocol)){const a=node('a','Kaynağı incele ↗');a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';content.append(a);}}catch{}
  details.append(summary,content);$('findings').append(details);
 }
}
async function loadDemo(){const current=++sequence;try{const response=await fetch('demo.json');if(!response.ok)throw new Error();const data=await response.json();if(current===sequence)applyReport(data,'',true);}catch{if(current===sequence)message('Örnek rapor açılamadı. Kendi JSON raporunu yükleyebilirsin.');}}
async function loadFile(file){if(!file)return;const current=++sequence;try{if(file.size>5*1024*1024)throw new Error('Dosya 5 MB sınırını aşıyor. Daha küçük bir rapor seç.');let data;try{data=JSON.parse(await file.text());}catch{throw new Error('Dosya geçerli JSON içermiyor. HardCheck JSON raporunu seç.');}if(current===sequence)applyReport(data,file.name,false);}catch(error){if(current===sequence)message(error.message);}finally{$('file').value='';}}
$('upload').addEventListener('click',()=>$('file').click());$('file').addEventListener('change',e=>loadFile(e.target.files[0]));
$('reset').addEventListener('click',loadDemo);$('search').addEventListener('input',render);$('severity').addEventListener('change',render);
for(const button of document.querySelectorAll('[data-status]'))button.addEventListener('click',()=>{statusFilter=button.dataset.status;render();});
const drop=document.querySelector('.import-card');drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('drag');});drop.addEventListener('dragleave',()=>drop.classList.remove('drag'));drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('drag');loadFile(e.dataTransfer.files[0]);});
$('help').addEventListener('click',()=>$('help-dialog').showModal());for(const id of ['close-help','understood'])$(id).addEventListener('click',()=>$('help-dialog').close());
$('download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json'}));const a=node('a');a.href=url;a.download=$('source-tag').textContent==='ÖRNEK RAPOR'?'hardcheck-ornek.json':'hardcheck-rapor.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
loadDemo();
