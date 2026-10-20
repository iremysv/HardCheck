'use strict';
// The server injects this token into the same-origin document, never a URL.
const sessionMeta=document.querySelector('meta[name="hardcheck-csrf"]');
if(sessionMeta){
 const csrf=sessionMeta.content;
 const start=$('real-scan'), state=$('local-state');
 let appliedGeneration=-1, pending=false;
 $('local-controls').hidden=false;
 const states={idle:'Hazır. Henüz gerçek tarama yapılmadı.',running:'Tarama sürüyor. Önceki veya yüklenen rapor varsa aşağıda ayrı olarak gösterilir.',completed:'Tarama tamamlandı. WARN, SKIP ve ERROR sonuçlarını ayrıca inceleyin.',error:'Tarama başarısız. Aşağıdaki önceki veya yüklenen rapor bu denemenin sonucu değildir.'};
 async function api(path,options={}){
  const response=await fetch(path,{...options,cache:'no-store',credentials:'same-origin',headers:{'X-HardCheck-CSRF':csrf,...options.headers}});
  if(!response.ok)throw new Error(response.status===409?'Başka bir tarama sürüyor veya tamamlanmış sonuç yok.':'Yerel servis isteği başarısız ('+response.status+').');
  return response;
 }
 function stale(){
  if(report && $('source-tag').textContent==='YEREL TARAMA'){
   $('source-tag').textContent='ÖNCEKİ TARAMA';
   $('report-caption').textContent='Bu rapor önceki tamamlanmış taramaya aittir; son denemenin sonucu değildir.';
  }
 }
 async function refresh(){
  try{
   const current=await (await api('/api/status')).json();
   state.textContent=current.supported?(states[current.state]+(current.error?' '+current.error:'')):'Gerçek tarama yalnızca Linux üzerinde desteklenir. JSON raporu yükleyebilir veya örneği inceleyebilirsiniz.';
   start.disabled=pending || current.state==='running' || !current.supported;
   for(const id of ['local-json','local-html'])$(id).disabled=current.state!=='completed';
   if(current.state==='running'||current.state==='error')stale();
   if(current.state==='completed' && appliedGeneration!==current.generation){
    const data=await (await api('/api/report.json')).json();
    // A concurrent tab can start another scan while this GET is in flight.
    const confirmed=await (await api('/api/status')).json();
    if(confirmed.state==='completed' && confirmed.generation===current.generation){
     ++sequence;applyReport(data,'Yerel tarama #'+current.generation,false);
     $('source-tag').textContent='YEREL TARAMA';
     $('report-caption').textContent='Bu yerel servisin tamamlanmış sonucu. Rapor dış sunucuya gönderilmedi.';
     appliedGeneration=current.generation;
    }
   }
  }catch(error){state.textContent=error.message+' Servis durmuş olabilir; HardCheck başlatıcısını yeniden açın.';start.disabled=true;for(const id of ['local-json','local-html'])$(id).disabled=true;stale();}
 }
 start.addEventListener('click',async()=>{
  if(pending || start.disabled)return;
  pending=true;start.disabled=true;stale();
  for(const id of ['local-json','local-html'])$(id).disabled=true;
  state.textContent='Tarama başlatılıyor…';
  try{await api('/api/scan',{method:'POST',body:''});}
  catch(error){state.textContent=error.message;}
  finally{pending=false;await refresh();}
 });
 for(const [id,kind] of [['local-json','json'],['local-html','html']]){
  $(id).addEventListener('click',async()=>{
   try{
    const response=await api('/api/report.'+kind);
    const url=URL.createObjectURL(await response.blob());
    const link=node('a');link.href=url;link.download='hardcheck-report.'+kind;link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
   }catch(error){state.textContent=error.message;await refresh();}
  });
 }
 // One request chain per tab; slow requests cannot accumulate polling loops.
 async function poll(){await refresh();setTimeout(poll,1000);}
 poll();
}
