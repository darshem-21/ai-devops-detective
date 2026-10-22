const $ = (id) => document.getElementById(id);
const money = (n) => "$" + Number(n || 0).toFixed(2);
function pct(n){return n === null || n === undefined ? "—" : `${n}%`;}
async function loadOverview(){
  try{
    const res=await fetch("/api/overview");
    if(!res.ok) throw new Error("API unavailable");
    const data=await res.json(), c=data.costs;
    $("nodes").textContent=data.cluster.nodes;
    $("pods").textContent=data.cluster.pods;
    $("totalCost").textContent=money(c.total_monthly_cost_usd);
    $("costTotal").textContent=money(c.total_monthly_cost_usd);
    $("savings").textContent=money(c.illustrative_monthly_savings_usd);
    $("costNote").textContent=c.note;
    $("costRows").innerHTML=c.workloads.map(w=>`<tr><td><strong>${escapeHtml(w.name)}</strong></td><td>${pct(w.cpu_utilization_pct)}</td><td>${pct(w.memory_utilization_pct)}</td><td>${money(w.monthly_cost_usd)}</td><td>${w.flags.length ? w.flags.map(f=>`<span class="tag">${escapeHtml(f)}</span>`).join("") : '<span class="hint">No obvious flag</span>'}</td></tr>`).join("");
  }catch(e){console.error(e);}
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
document.querySelectorAll("[data-example]").forEach(b=>b.addEventListener("click",()=>{$("logs").value=b.dataset.example;}));
$("refresh").addEventListener("click",loadOverview);
$("diagnose").addEventListener("click",async()=>{
  const logs=$("logs").value.trim(); if(!logs){$("logs").focus();return;}
  const btn=$("diagnose");btn.disabled=true;btn.textContent="Analyzing…";
  const box=$("diagnosis");box.classList.remove("hidden");box.innerHTML="<p>Analyzing supplied text…</p>";
  try{
    const res=await fetch("/api/troubleshoot",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({logs})});
    const data=await res.json(); if(!res.ok) throw new Error(data.detail||"Request failed");
    let html=`<h3>${escapeHtml(data.summary||"Analysis result")}</h3>`;
    for(const f of (data.findings||[])) html+=`<div class="finding"><strong>${escapeHtml(f.issue)} <span class="tag">${escapeHtml(f.severity)}</span></strong><p>${escapeHtml(f.likely_cause)}</p><ul>${(f.checks||[]).map(c=>`<li>${escapeHtml(c)}</li>`).join("")}</ul></div>`;
    if(data.ai_explanation) html+=`<div class="finding"><strong>AI explanation</strong><p>${escapeHtml(data.ai_explanation).replace(/\n/g,"<br>")}</p></div>`;
    if(data.ai_note) html+=`<p class="hint">${escapeHtml(data.ai_note)}</p>`;
    html+='<p class="hint">Suggestions are advisory. Verify the diagnosis and review commands before using them.</p>';
    box.innerHTML=html;
  }catch(e){box.innerHTML=`<p>Analysis failed: ${escapeHtml(e.message)}</p>`;}
  finally{btn.disabled=false;btn.textContent="✦ Analyze incident";}
});
loadOverview();
