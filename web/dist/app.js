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
let pageIndex=0, filterSignature='';
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
function message(text){$('message').textContent=text;$('message').hidden=!text;$('notice').hidden=true;}
function applyReport(data,name,demo,remember=true,source="upload"){
 report=validateReport(data);statusFilter='ALL';pageIndex=0;filterSignature='';$('sort').value='priority';$('page-size').value='10';$('search').value='';$('severity').value='ALL';$('category').value='ALL';
 $('source-tag').textContent=demo?'ÖRNEK RAPOR':source==='local'?'YEREL TARAMA':source==='previous'?'ÖNCEKİ TARAMA':'YÜKLENEN RAPOR';$('report-name').textContent=demo?'Örnek yapılandırma':name;
 $('report-caption').textContent=demo?'Arayüzü keşfetmen için hazırlanmış temsili sonuçlar. Gerçek bir sistem taraması değildir.':'Dosya yalnızca bu tarayıcı oturumunda açık. Kaynak: HardCheck '+String(data.hardcheck_version || '—')+' · Rapor dili: '+(data.language==='tr'?'Türkçe':data.language==='en'?'İngilizce':'Belirtilmemiş');
 if(!demo && source==='local')$('report-caption').textContent='Bu yerel servisin tamamlanmış sonucu. Rapor dış sunucuya gönderilmedi.';
 if(!demo && source==='previous')$('report-caption').textContent='Oturum geçmişinden açılan tamamlanmış tarama; son taramanın sonucu olmayabilir.';
 const counts=Object.fromEntries(statuses.map(s=>[s,data.findings.filter(f=>f.status===s).length]));
 const total=data.findings.length, assessed=counts.PASS+counts.FAIL;
 const score=assessed?Math.round(counts.PASS/assessed*100):null;
 $('total').textContent=total;$('failed').textContent=counts.FAIL;$('warned').textContent=counts.WARN;$('skipped').textContent=counts.SKIP;$('errors').textContent=counts.ERROR;
 $('coverage').textContent=assessed+'/'+total+' kesin değerlendirildi'+(data.scope.collected_controls>total?' · '+(data.scope.collected_controls-total)+' kaynakta filtrelendi':'');
 $('score-coverage').textContent=assessed+'/'+total+' kontrol kesin değerlendirildi'+(total?' · %'+Math.round(assessed/total*100)+' kapsam':'');
 $('download').disabled=false;
 $('score').textContent=score===null?'—':'%'+score;$('score-bar').style.width=(score || 0)+'%';message('');
 if(remember){reportHistory.unshift({data,name:name || 'Örnek yapılandırma',demo,source,opened:new Date().toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'})});reportHistory=reportHistory.slice(0,10);}
 updateDashboard(counts,score);updateScope(data,demo);render();renderHistory();
}
function addSection(parent,title,text,wide=false){const section=node('div',undefined,wide?'detail-wide':'');section.append(node('h3',title),node('p',text || 'Belirtilmemiş'));parent.append(section);}
function formatEvidence(e){
 const value=e.key==='mode_bits' && Number.isSafeInteger(e.value)?e.value.toString(8).padStart(4,'0'):(Object.hasOwn(valueLabels,e.value)?valueLabels[e.value]:String(e.value));
 return (Object.hasOwn(evidenceLabels,e.key)?evidenceLabels[e.key]:e.key)+': '+value;
}
function render(){
 if(!report)return;
 document.querySelectorAll('[data-status]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.status===statusFilter)));
 const query=$('search').value.toLocaleLowerCase('tr').trim(), severity=$('severity').value, category=$('category').value;
 const filtered=report.findings.filter(f=>(statusFilter==='ALL'||(statusFilter==='UNCERTAIN'?['WARN','SKIP','ERROR'].includes(f.status):f.status===statusFilter)) && (category==='ALL'||f.category===category) && (severity==='ALL'||f.severity===severity) && (!query||[f.check_id,f.title,f.category].join(' ').toLocaleLowerCase('tr').includes(query)));
 const sort=$('sort').value || 'priority';
 const signature=JSON.stringify([query,severity,category,statusFilter,sort,$('page-size').value]);
 if(signature!==filterSignature){pageIndex=0;filterSignature=signature;}
 filtered.sort(compareFindings(sort));
 const size=Number($('page-size').value)||10, pages=Math.max(1,Math.ceil(filtered.length/size));pageIndex=Math.min(pageIndex,pages-1);
 $('previous-page').disabled=pageIndex===0;$('next-page').disabled=pageIndex>=pages-1;$('page-number').textContent=(pageIndex+1)+' / '+pages;
 $('findings').replaceChildren();$('count').textContent=report.findings.length;$('visible-count').textContent=filtered.length+' / '+report.findings.length+' eşleşme'+(filtered.length?' · '+(pageIndex*size+1)+'–'+Math.min((pageIndex+1)*size,filtered.length):'');
 $('clear-filters').disabled=!query && severity==='ALL' && category==='ALL' && statusFilter==='ALL';
 if(!filtered.length){$('findings').append(node('p',report.findings.length?'Bu filtrelerle eşleşen bulgu yok. Aramayı veya filtreleri değiştir.':'Bu raporda gösterilen bulgu yok. Bu, sistemin güvenli olduğu anlamına gelmez.','empty'));return;}
 for(const f of filtered.slice(pageIndex*size,(pageIndex+1)*size)){
  const details=node('details'), summary=node('summary'), label=node('span',undefined,'finding-label');
  label.append(node('span',f.check_id,'check-id'),node('span',f.title,'finding-title'));
  summary.append(label,node('span',severityLabels[f.severity],'severity'),node('span',f.status,'badge '+f.status),node('span','›','chevron'));
  const content=node('div',undefined,'detail-content');
  addSection(content,'Beklenen',f.expected);addSection(content,'Gözlem / kanıt',f.evidence.map(formatEvidence).join('\n'));
  addSection(content,'Neden önemli?',f.rationale);addSection(content,'Önerilen adım',f.remediation);addSection(content,'Değerlendirme notu',f.note,true);
  try{const url=new URL(f.reference);if(['https:','http:'].includes(url.protocol)){const a=node('a','Kaynağı incele ↗');a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';content.append(a);}}catch{}
  details.append(summary,content);$('findings').append(details);
 }
}
async function loadDemo(){const current=++sequence;try{const response=await fetch('demo.json');if(!response.ok)throw new Error();const data=await response.json();if(current===sequence){demoData=data;applyReport(data,'',true);}}catch{if(current===sequence)message('Örnek rapor açılamadı. Kendi JSON raporunu yükleyebilirsin.');}}
async function loadFile(file){if(!file)return;const current=++sequence;try{if(file.size>5*1024*1024)throw new Error('Dosya 5 MB sınırını aşıyor. Daha küçük bir rapor seç.');let data;try{data=JSON.parse(await file.text());}catch{throw new Error('Dosya geçerli JSON içermiyor. HardCheck JSON raporunu seç.');}if(current===sequence){applyReport(data,file.name,false);location.hash='overview';$('notice').textContent=file.name+' yüklendi. '+data.findings.length+' kontrol incelemeye hazır.';$('notice').hidden=false;}}catch(error){if(current===sequence)message(error.message);}finally{$('file').value='';}}
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
 $('report-list').replaceChildren();$('compare-before').replaceChildren();$('compare-after').replaceChildren();
 $('comparison-result').replaceChildren(node('p',reportHistory.length<2?'Karşılaştırmak için en az iki rapor açın.':'İki rapor seçip karşılaştırın.','empty'));
 reportHistory.forEach((entry,i)=>{for(const id of ['compare-before','compare-after']){const option=node('option',(i+1)+'. '+entry.name+(entry.demo?' [ÖRNEK]':'')+' · '+entry.opened);option.value=String(i);$(id).append(option);}});
 $('compare-before').value=reportHistory.length>1?'1':'0';$('compare-after').value='0';$('compare').disabled=reportHistory.length<2;
 for(const entry of reportHistory){
  const row=node('article',undefined,'panel report-item'),info=node('div',undefined,'report-info');
  const passed=entry.data.findings.filter(f=>f.status==='PASS').length,failed=entry.data.findings.filter(f=>f.status==='FAIL').length;
  info.append(node('strong',entry.name+(entry.demo?' · ÖRNEK':'')),node('p','Açılış '+entry.opened+' · '+entry.data.findings.length+' kontrol · '+failed+' başarısız'));
  const inspect=node('button','İncele','button secondary');inspect.addEventListener('click',()=>{applyReport(entry.data,entry.name,entry.demo,false,entry.source==='local'?'previous':entry.source);location.hash='overview';});
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

function compareFindings(sort){
 const order={ERROR:0,FAIL:1,WARN:2,SKIP:3,PASS:4};
 return (a,b)=>sort==='title'?a.title.localeCompare(b.title,'tr')||a.check_id.localeCompare(b.check_id):sort==='id'?a.check_id.localeCompare(b.check_id):order[a.status]-order[b.status]||severities.indexOf(b.severity)-severities.indexOf(a.severity)||a.check_id.localeCompare(b.check_id);
}
function updateScope(data,demo){
 const hidden=data.scope.collected_controls-data.findings.length;
 const uncertain=data.findings.filter(f=>['WARN','SKIP','ERROR'].includes(f.status)).length;
 const scanErrors=data.scan_summary?.counts?.ERROR;
 const visibleErrors=data.findings.filter(f=>f.status==='ERROR').length;
 const notes=[];
 if(hidden)notes.push(hidden+' kontrol kaynak raporda filtrelenmiş; burada incelenemiyor.');
 if(Number.isSafeInteger(scanErrors) && scanErrors>visibleErrors)notes.push((scanErrors-visibleErrors)+' ERROR sonucu kaynak raporda gizli. Puan bu hataları kapsamaz.');
 if(uncertain)notes.push(uncertain+' kontrol belirsiz, atlanmış veya tamamlanamamış.');
 notes.push('Puan yalnızca gösterilen PASS ve FAIL sonuçlarına dayanır.');
 $('scope-notice').textContent=notes.join(' ');$('scope-notice').hidden=false;
 const env=Array.isArray(data.scope.environments)?data.scope.environments[0]:null;
 $('host-meta').textContent=demo?'Temsili sonuçlar':env && typeof env.distribution==='string'?env.distribution.slice(0,100):'Ortam bilgisi belirtilmemiş';
}
function compareReports(before,after){
 const left=new Map(before.findings.map(f=>[f.check_id,f])),right=new Map(after.findings.map(f=>[f.check_id,f]));
 return [...new Set([...left.keys(),...right.keys()])].sort().map(id=>{
  const a=left.get(id),b=right.get(id);
  const kind=!a?'added':!b?'removed':a.status==='FAIL'&&b.status==='PASS'?'resolved':a.status==='PASS'&&b.status==='FAIL'?'regressed':a.status!==b.status?'changed':a.severity!==b.severity?'severity':'same';
  return {id,before:a,after:b,kind};
 });
}
function showComparison(){
 const before=reportHistory[Number($('compare-before').value)],after=reportHistory[Number($('compare-after').value)];
 $('comparison-result').replaceChildren();
 if(!before||!after||before===after){$('comparison-result').append(node('p','İki farklı rapor seçin.','empty'));return;}
 const all=compareReports(before.data,after.data),changed=all.filter(row=>row.kind!=='same');
 const names={added:'Yalnızca sonraki raporda',removed:'Sonraki raporda yok',resolved:'FAIL → PASS',regressed:'PASS → FAIL',changed:'Durum değişti',severity:'Önem değişti'};
 const summary=node('div',undefined,'comparison-summary');
 for(const [label,kind] of [['Düzelmiş','resolved'],['Yeni uygunsuzluk','regressed'],['Diğer değişim',null]]){const card=node('div');card.append(node('strong',changed.filter(r=>kind?r.kind===kind:!['resolved','regressed'].includes(r.kind)).length),node('span',label));summary.append(card);}
 $('comparison-result').append(summary);
 if(!changed.length)$('comparison-result').append(node('p','Kontrol kodları, durumlar ve önem düzeyleri aynı. Kanıt veya açıklama metinleri karşılaştırılmaz.','empty'));
 for(const row of changed){const line=node('div',undefined,'comparison-row'),info=node('div');info.append(node('strong',row.id),node('small',(row.after||row.before).title));
 const status=node('span',(row.before?.status||'Yok')+' → '+(row.after?.status||'Yok'),'comparison-status');
 const note=node('span',row.kind==='severity'?severityLabels[row.before.severity]+' → '+severityLabels[row.after.severity]:names[row.kind], 'change-label '+row.kind);
 line.append(info,status,note);$('comparison-result').append(line);}
}
function clearFilters(){statusFilter='ALL';$('search').value='';$('severity').value='ALL';$('category').value='ALL';pageIndex=0;render();}
$('clear-filters').addEventListener('click',clearFilters);$('sort').addEventListener('change',render);$('page-size').addEventListener('change',render);
$('previous-page').addEventListener('click',()=>{pageIndex=Math.max(0,pageIndex-1);render();});$('next-page').addEventListener('click',()=>{pageIndex++;render();});
$('compare').addEventListener('click',showComparison);
for(const id of ['compare-before','compare-after'])$(id).addEventListener('change',()=>{$('comparison-result').replaceChildren(node('p','Seçim değişti. Sonuçları güncellemek için Karşılaştır’a basın.','empty'));});
window.addEventListener('hashchange',navigate);navigate();
if(!document.querySelector('meta[name="hardcheck-csrf"]'))loadDemo();
else {$('source-tag').textContent='RAPOR BEKLENİYOR';$('report-name').textContent='Henüz gerçek tarama yapılmadı';$('report-caption').textContent='Gerçek taramayı başlatın veya JSON raporu yükleyin.';$('count').textContent='0';}
