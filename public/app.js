/* =====================================================
   CyberPulse v3.1 — Frontend Application Logic
   Connects to real Node.js scanning backend
   ===================================================== */

const API = '';  // same origin

/* ---------- Matrix Rain ---------- */
!function(){
    const c=document.getElementById('matrixCanvas'); if(!c)return;
    const x=c.getContext('2d'); c.width=innerWidth; c.height=innerHeight;
    const chars='アイウエオカキクケコ0123456789ABCDEF'; const fs=12;
    const cols=Math.floor(c.width/fs); const drops=Array(cols).fill(1);
    setInterval(()=>{
        x.fillStyle='rgba(10,14,23,.05)'; x.fillRect(0,0,c.width,c.height);
        x.fillStyle='#00ff88'; x.font=fs+'px monospace';
        for(let i=0;i<drops.length;i++){
            x.fillText(chars[Math.random()*chars.length|0],i*fs,drops[i]*fs);
            if(drops[i]*fs>c.height&&Math.random()>.975)drops[i]=0; drops[i]++;
        }
    },50);
    addEventListener('resize',()=>{c.width=innerWidth;c.height=innerHeight});
}();

/* ---------- Navigation ---------- */
document.querySelectorAll('.nav-item').forEach(item=>{
    item.addEventListener('click',e=>{
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
        item.classList.add('active');
        document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
        const panel=document.getElementById('panel-'+item.dataset.panel);
        if(panel)panel.classList.add('active');
        document.getElementById('breadcrumb').textContent=item.querySelector('.nav-label').textContent;
        if(innerWidth<=1024)document.getElementById('sidebar').classList.add('collapsed');
    });
});
document.getElementById('sidebarToggle')?.addEventListener('click',()=>{
    document.getElementById('sidebar').classList.toggle('collapsed');
});
if(innerWidth<=1024)document.getElementById('sidebar').classList.add('collapsed');

/* ---------- Clock ---------- */
setInterval(()=>{
    const n=new Date();
    document.getElementById('topbarClock').textContent=n.toLocaleDateString('vi-VN')+' | '+n.toLocaleTimeString('en-US',{hour12:false});
},1000);

/* ---------- Toast ---------- */
function toast(msg,type='info'){
    const c=document.getElementById('toastContainer');
    const icons={success:'✓',error:'✗',info:'ℹ',warning:'⚠'};
    const t=document.createElement('div');
    t.className=`toast toast-${type}`;
    t.innerHTML=`<span>${icons[type]||'ℹ'}</span> ${msg}`;
    c.appendChild(t); setTimeout(()=>t.remove(),4000);
}

/* ---------- Utility ---------- */
function esc(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

function renderFindings(findings){
    if(!findings||!findings.length) return '<p style="color:var(--text-muted);text-align:center;padding:1rem;">Không phát hiện lỗ hổng nào.</p>';
    return findings.map(f=>`
        <div class="finding-card sev-${f.severity||'info'}">
            <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.2rem;">
                <span class="badge badge-${f.severity||'info'}">${(f.severity||'info').toUpperCase()}</span>
                <span class="finding-title">${esc(f.title)}</span>
            </div>
            ${f.detail?`<div class="finding-detail">${esc(f.detail)}</div>`:''}
            ${f.evidence?`<div class="file-snippet">${esc(JSON.stringify(f.evidence,null,2))}</div>`:''}
            <div class="finding-meta"><span>Module: ${esc(f.module||'—')}</span></div>
        </div>
    `).join('');
}

/* =====================================================
   SCANNER — connects to backend
   ===================================================== */
const Scanner = {
    scanning: false,
    timerInterval: null,

    /* ---- Full Scan (SSE streaming) ---- */
    async fullScan(){
        const target=document.getElementById('fullscanTarget').value.trim();
        if(!target){toast('Nhập target URL','warning');return;}
        if(this.scanning){toast('Đang scan...','warning');return;}
        this.scanning=true;

        const btn=document.getElementById('btnFullScan');
        btn.disabled=true; btn.querySelector('.btn-text').textContent='⏳ SCANNING...';

        const prog=document.getElementById('fullscanProgress');
        const log=document.getElementById('fullscanLog');
        const summary=document.getElementById('fullscanSummary');
        const results=document.getElementById('fullscanResults');
        prog.style.display='block'; log.innerHTML=''; summary.style.display='none'; results.innerHTML='';

        // Timer
        let sec=0;
        const timer=document.getElementById('fullscanTimer');
        this.timerInterval=setInterval(()=>{sec++;timer.textContent=`${String(sec/60|0).padStart(2,'0')}:${String(sec%60).padStart(2,'0')}`;},1000);

        const moduleCount=16; let completed=0;
        const fill=document.getElementById('fullscanFill');

        try{
            const resp=await fetch(API+'/api/fullscan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
            const reader=resp.body.getReader();
            const decoder=new TextDecoder();
            let buffer='';

            while(true){
                const{done,value}=await reader.read();
                if(done)break;
                buffer+=decoder.decode(value,{stream:true});
                const lines=buffer.split('\n');
                buffer=lines.pop();

                for(const line of lines){
                    if(line.startsWith('event: ')){
                        var evtType=line.slice(7).trim();
                    } else if(line.startsWith('data: ')){
                        try{
                            const data=JSON.parse(line.slice(6));
                            if(evtType==='status'){
                                log.innerHTML+=`<div class="log-line"><span class="log-module">[${esc(data.module)}]</span> ${esc(data.message)}</div>`;
                                log.scrollTop=log.scrollHeight;
                            } else if(evtType==='result'){
                                completed++;
                                fill.style.width=((completed/moduleCount)*100)+'%';
                                if(data.data?.findings?.length){
                                    for(const f of data.data.findings){
                                        log.innerHTML+=`<div class="log-line"><span class="log-finding">⚠ [${esc(f.severity?.toUpperCase())}]</span> ${esc(f.title)}</div>`;
                                    }
                                    log.scrollTop=log.scrollHeight;
                                }
                            } else if(evtType==='done'){
                                this.renderFullScanResults(data, summary, results);
                            } else if(evtType==='error'){
                                log.innerHTML+=`<div class="log-line" style="color:var(--accent-danger);">ERROR: ${esc(data.message)}</div>`;
                            }
                        }catch(e){}
                    }
                }
            }
        }catch(e){
            toast('Lỗi kết nối: '+e.message,'error');
            log.innerHTML+=`<div class="log-line" style="color:var(--accent-danger);">Connection error: ${esc(e.message)}</div>`;
        }

        clearInterval(this.timerInterval);
        this.scanning=false;
        btn.disabled=false; btn.querySelector('.btn-text').textContent='🚀 FULL SCAN';
        fill.style.width='100%';
        toast('Full scan hoàn tất!','success');
    },

    renderFullScanResults(data, summaryEl, resultsEl){
        const s=data.summary;
        summaryEl.style.display='block';
        summaryEl.innerHTML=`
            <div class="summary-grid">
                <div class="summary-card"><div class="summary-value" style="color:#ff4444">${s.critical}</div><span class="summary-label">Critical</span></div>
                <div class="summary-card"><div class="summary-value" style="color:#ff4757">${s.high}</div><span class="summary-label">High</span></div>
                <div class="summary-card"><div class="summary-value" style="color:#ffa502">${s.medium}</div><span class="summary-label">Medium</span></div>
                <div class="summary-card"><div class="summary-value" style="color:#00d4ff">${s.low}</div><span class="summary-label">Low</span></div>
                <div class="summary-card"><div class="summary-value" style="color:#3b82f6">${s.info}</div><span class="summary-label">Info</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-primary)">${s.total}</div><span class="summary-label">Total</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-secondary)">${s.duration}s</div><span class="summary-label">Duration</span></div>
            </div>
        `;

        // Group findings by severity
        const groups={critical:[],high:[],medium:[],low:[],info:[]};
        for(const f of data.findings){(groups[f.severity]||groups.info).push(f);}
        let html='<div class="result-section"><div class="result-section-title">TẤT CẢ PHÁT HIỆN ('+data.findings.length+')</div>';
        for(const sev of ['critical','high','medium','low','info']){
            if(groups[sev].length) html+=renderFindings(groups[sev]);
        }
        html+='</div>';

        // Export button
        html+=`<div style="margin-top:1rem;display:flex;gap:.5rem;">
            <button class="cyber-btn primary" onclick="Scanner.exportReport()" style="font-size:.72rem;padding:.5rem 1rem;">📄 XUẤT BÁO CÁO HTML</button>
            <button class="cyber-btn" onclick="Scanner.exportJSON()" style="font-size:.72rem;padding:.5rem 1rem;background:var(--bg-tertiary);color:var(--text-secondary);border:1px solid var(--border-color);">💾 XUẤT JSON</button>
        </div>`;

        resultsEl.innerHTML=html;

        // Store for export
        Scanner._lastResults=data;
    },

    /* ---- Individual Module ---- */
    async runModule(mod){
        const input=document.getElementById(mod+'Target');
        if(!input){toast('Input not found','error');return;}
        const target=input.value.trim();
        if(!target){toast('Nhập target','warning');return;}

        const container=document.getElementById(mod+'Results');
        container.innerHTML='<div style="text-align:center;padding:2rem;"><div style="font-size:1.5rem;animation:liveBlink 1s infinite;">⟳</div><p style="color:var(--text-muted);margin-top:.5rem;font-family:var(--font-mono);font-size:.8rem;">Đang scan thực tế...</p></div>';

        try{
            const resp=await fetch(API+'/api/'+mod,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
            const data=await resp.json();
            if(data.error){container.innerHTML=`<p style="color:var(--accent-danger);padding:1rem;">❌ ${esc(data.error)}</p>`;toast(data.error,'error');return;}
            container.innerHTML=this.renderModuleResult(mod,data);
            toast(mod.toUpperCase()+' scan hoàn tất!','success');
        }catch(e){
            container.innerHTML=`<p style="color:var(--accent-danger);padding:1rem;">❌ Lỗi: ${esc(e.message)}</p>`;
            toast('Lỗi: '+e.message,'error');
        }
    },

    renderModuleResult(mod,data){
        switch(mod){
            case 'crawl': return this.renderCrawl(data);
            case 'headers': return this.renderHeaders(data);
            case 'tech': return this.renderTech(data);
            case 'files': return this.renderFiles(data);
            case 'exposure': return this.renderExposure(data);
            case 'xss': return this.renderAttack('XSS',data);
            case 'sqli': return this.renderAttack('SQL Injection',data);
            case 'lfi': return this.renderAttack('LFI / Path Traversal',data);
            case 'cors': return this.renderCORS(data);
            case 'redirect': return this.renderAttack('Open Redirect',data);
            case 'ssl': return this.renderSSL(data);
            case 'dns': return this.renderDNS(data);
            case 'subdomains': return this.renderSubdomains(data);
            default: return '<pre>'+esc(JSON.stringify(data,null,2))+'</pre>';
        }
    },

    renderCrawl(d){
        return `<div class="result-section">
            <div class="result-section-title">CRAWL RESULTS</div>
            <div class="summary-grid">
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-primary)">${d.pages?.length||0}</div><span class="summary-label">Pages</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-secondary)">${d.forms?.length||0}</div><span class="summary-label">Forms</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-warning)">${d.paramUrls?.length||0}</div><span class="summary-label">URLs with params</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--text-secondary)">${d.links?.length||0}</div><span class="summary-label">Total links</span></div>
            </div>
            ${d.pages?.length?`<table class="result-table"><thead><tr><th>URL</th><th>Status</th></tr></thead><tbody>${d.pages.map(p=>`<tr><td>${esc(p.url)}</td><td><span class="badge badge-${p.status===200?'safe':p.status>=400?'high':'info'}">${p.status}</span></td></tr>`).join('')}</tbody></table>`:''}
            ${d.forms?.length?`<div class="result-section-title" style="margin-top:1rem;">FORMS FOUND</div><table class="result-table"><thead><tr><th>Action</th><th>Method</th><th>Inputs</th></tr></thead><tbody>${d.forms.map(f=>`<tr><td>${esc(f.action)}</td><td><span class="badge badge-info">${f.method}</span></td><td>${f.inputs.map(i=>esc(i.name||'(unnamed)')).join(', ')}</td></tr>`).join('')}</tbody></table>`:''}
        </div>`;
    },

    renderHeaders(d){
        const scoreColor=d.score>=80?'#00ff88':d.score>=50?'#ffa502':'#ff4757';
        return `<div class="result-section">
            <div class="result-section-title">SECURITY HEADERS — Score: <span style="color:${scoreColor}">${d.score}/100</span></div>
            ${d.checks.map(c=>`
                <div class="header-check">
                    <span class="header-check-icon">${c.present?'✅':'❌'}</span>
                    <span class="header-check-name">${esc(c.name)}</span>
                    <span class="header-check-value">${c.present?esc(String(c.value).substring(0,100)):('<span class="badge badge-'+c.severity+'">MISSING</span>')}</span>
                </div>
            `).join('')}
            ${d.findings?.length?'<div class="result-section-title" style="margin-top:1rem;">FINDINGS</div>'+renderFindings(d.findings):''}
        </div>`;
    },

    renderTech(d){
        const byCategory={};
        for(const t of d.technologies||[]){(byCategory[t.category]=byCategory[t.category]||[]).push(t);}
        let html='<div class="result-section"><div class="result-section-title">DETECTED TECHNOLOGIES</div>';
        for(const[cat,techs]of Object.entries(byCategory)){
            html+=`<div style="margin-bottom:.8rem;"><div class="tech-category" style="margin-bottom:.3rem;">${esc(cat)}</div><div>${techs.map(t=>`<span class="tech-card" title="Source: ${esc(t.source)}, Confidence: ${esc(t.confidence)}">${esc(t.name)}</span>`).join('')}</div></div>`;
        }
        html+='</div>';
        if(d.findings?.length) html+=renderFindings(d.findings);
        return html;
    },

    renderFiles(d){
        return `<div class="result-section">
            <div class="result-section-title">SENSITIVE FILES — ${d.found?.length||0} found / ${d.scanned} scanned</div>
            ${d.found?.length?d.found.map(f=>`
                <div class="finding-card sev-${f.severity}">
                    <div style="display:flex;align-items:center;gap:.5rem;">
                        <span class="badge badge-${f.severity}">${(f.severity).toUpperCase()}</span>
                        <span class="finding-title">${esc(f.path)}</span>
                        <span style="font-size:.65rem;color:var(--text-muted);margin-left:auto;">${f.status} • ${f.size} bytes</span>
                    </div>
                    <div class="finding-detail">${esc(f.desc)}</div>
                    ${f.snippet?`<div class="file-snippet">${esc(f.snippet)}</div>`:''}
                </div>
            `).join(''):'<p style="color:var(--accent-primary);text-align:center;padding:1rem;">✅ Không tìm thấy file nhạy cảm nào.</p>'}
        </div>`;
    },

    renderExposure(d){
        const c=d.checked||{};
        return `<div class="result-section">
            <div class="result-section-title">EXPOSURE CHECKS — ${d.findings?.length||0} findings</div>
            <div class="summary-grid">
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-primary)">${c.endpoints||0}</div><span class="summary-label">Endpoints</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-secondary)">${c.directories||0}</div><span class="summary-label">Directories</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-warning)">${c.scripts||0}</div><span class="summary-label">JS files</span></div>
                <div class="summary-card"><div class="summary-value" style="color:var(--accent-danger)">${d.secrets?.length||0}</div><span class="summary-label">Secret hits</span></div>
            </div>
            ${d.findings?.length?renderFindings(d.findings):'<p style="color:var(--accent-primary);text-align:center;padding:1rem;">✅ Không phát hiện exposure đáng chú ý.</p>'}
            ${d.methods?.length?`<div class="result-section-title" style="margin-top:1rem;">HTTP METHODS</div><table class="result-table"><thead><tr><th>URL</th><th>Allow</th><th>Risky</th></tr></thead><tbody>${d.methods.map(m=>`<tr><td>${esc(m.url)}</td><td>${esc(m.allow)}</td><td>${(m.risky||[]).map(x=>`<span class="badge badge-medium">${esc(x)}</span>`).join(' ')||'—'}</td></tr>`).join('')}</tbody></table>`:''}
            ${d.endpoints?.length?`<div class="result-section-title" style="margin-top:1rem;">EXPOSED ENDPOINTS</div><table class="result-table"><thead><tr><th>Path</th><th>Status</th><th>Type</th></tr></thead><tbody>${d.endpoints.map(e=>`<tr><td>${esc(e.path)}</td><td>${e.status}</td><td><span class="badge badge-info">${esc(e.type)}</span></td></tr>`).join('')}</tbody></table>`:''}
            ${d.secrets?.length?`<div class="result-section-title" style="margin-top:1rem;">CLIENT-SIDE SECRET PATTERNS (REDACTED)</div><table class="result-table"><thead><tr><th>File</th><th>Type</th><th>Redacted</th></tr></thead><tbody>${d.secrets.map(s=>`<tr><td>${esc(s.file)}</td><td>${esc(s.type)}</td><td>${esc(s.redacted)}</td></tr>`).join('')}</tbody></table>`:''}
        </div>`;
    },

    renderAttack(title,d){
        return `<div class="result-section">
            <div class="result-section-title">${esc(title)} RESULTS — ${d.findings?.length||0} vulnerabilities found</div>
            ${d.tested?.length?`<p style="font-size:.78rem;color:var(--text-muted);margin-bottom:.8rem;">Tested ${d.tested.length} parameters/inputs</p>`:''}
            ${d.findings?.length?renderFindings(d.findings):'<p style="color:var(--accent-primary);text-align:center;padding:1rem;">✅ Không phát hiện lỗ hổng.</p>'}
        </div>`;
    },

    renderCORS(d){
        return `<div class="result-section">
            <div class="result-section-title">CORS CONFIGURATION</div>
            <table class="result-table"><thead><tr><th>Origin Tested</th><th>ACAO</th><th>Credentials</th></tr></thead><tbody>
            ${(d.results||[]).map(r=>`<tr><td>${esc(r.origin)}</td><td>${r.acao?esc(r.acao):'—'}</td><td>${r.acac||'—'}</td></tr>`).join('')}
            </tbody></table>
            ${d.findings?.length?renderFindings(d.findings):'<p style="color:var(--accent-primary);text-align:center;padding:1rem;margin-top:.5rem;">✅ CORS cấu hình an toàn.</p>'}
        </div>`;
    },

    renderSSL(d){
        const cert=d.certificate;
        return `<div class="result-section">
            <div class="result-section-title">SSL/TLS ANALYSIS</div>
            ${d.supported?`
                <div class="result-item"><span class="result-key">Protocol</span><span class="result-value">${esc(d.protocol||'—')}</span></div>
                <div class="result-item"><span class="result-key">Cipher</span><span class="result-value">${esc(d.cipher?.name||'—')}</span></div>
                <div class="result-item"><span class="result-key">Days Until Expiry</span><span class="result-value" style="color:${d.daysUntilExpiry<30?'var(--accent-danger)':'var(--accent-primary)'}">${d.daysUntilExpiry??'—'}</span></div>
                ${cert?`
                    <div class="result-section-title" style="margin-top:1rem;">CERTIFICATE</div>
                    <div class="result-item"><span class="result-key">Subject</span><span class="result-value">${esc(JSON.stringify(cert.subject))}</span></div>
                    <div class="result-item"><span class="result-key">Issuer</span><span class="result-value">${esc(JSON.stringify(cert.issuer))}</span></div>
                    <div class="result-item"><span class="result-key">Valid From</span><span class="result-value">${esc(cert.validFrom||'—')}</span></div>
                    <div class="result-item"><span class="result-key">Valid To</span><span class="result-value">${esc(cert.validTo||'—')}</span></div>
                    <div class="result-item"><span class="result-key">Key Size</span><span class="result-value">${cert.bits??'—'} bits</span></div>
                    <div class="result-item"><span class="result-key">SANs</span><span class="result-value">${esc(cert.subjectAltName||'—')}</span></div>
                `:''}
            `:'<p style="color:var(--accent-danger);">SSL không khả dụng hoặc kết nối thất bại.</p>'}
            ${d.findings?.length?'<div class="result-section-title" style="margin-top:1rem;">FINDINGS</div>'+renderFindings(d.findings):''}
        </div>`;
    },

    renderDNS(d){
        const rec=d.records||{};
        let html=`<div class="result-section"><div class="result-section-title">DNS RECORDS — ${esc(d.domain||'')}</div>`;
        for(const[type,values]of Object.entries(rec)){
            if(!values)continue;
            html+=`<div style="margin-bottom:.8rem;"><strong style="color:var(--accent-secondary);font-family:var(--font-mono);font-size:.75rem;">${type}</strong>`;
            if(Array.isArray(values)){
                html+='<div style="margin-top:.3rem;">'+values.map(v=>`<div style="font-family:var(--font-mono);font-size:.72rem;color:var(--text-secondary);padding:.15rem 0;">${esc(typeof v==='object'?JSON.stringify(v):String(v))}</div>`).join('')+'</div>';
            } else {
                html+=`<div style="font-family:var(--font-mono);font-size:.72rem;color:var(--text-secondary);padding:.15rem 0;">${esc(JSON.stringify(values))}</div>`;
            }
            html+='</div>';
        }
        html+='</div>';
        if(d.findings?.length) html+=renderFindings(d.findings);
        return html;
    },

    renderSubdomains(d){
        return `<div class="result-section">
            <div class="result-section-title">SUBDOMAINS — ${d.found?.length||0} discovered for ${esc(d.domain||'')}</div>
            ${d.found?.length?`<table class="result-table"><thead><tr><th>Subdomain</th><th>IP</th><th>Source</th></tr></thead><tbody>
            ${d.found.map(s=>`<tr><td style="color:var(--accent-secondary)">${esc(s.subdomain)}</td><td>${s.ip?esc(Array.isArray(s.ip)?s.ip.join(', '):s.ip):'—'}</td><td><span class="badge badge-info">${esc(s.source)}</span></td></tr>`).join('')}
            </tbody></table>`:'<p style="text-align:center;color:var(--text-muted);padding:1rem;">Không tìm thấy subdomain.</p>'}
            ${d.findings?.length?renderFindings(d.findings):''}
        </div>`;
    },

    /* ---- Export ---- */
    exportReport(){
        const d=this._lastResults; if(!d){toast('Không có dữ liệu','warning');return;}
        const html=`<!DOCTYPE html><html><head><meta charset="utf-8"><title>CyberPulse Report</title>
        <style>body{font-family:system-ui;background:#0a0e17;color:#e2e8f0;padding:2rem;max-width:900px;margin:0 auto}h1{color:#00ff88;border-bottom:2px solid #00ff8833;padding-bottom:1rem}h2{color:#00d4ff;margin-top:2rem}.badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.75rem;font-weight:700}.critical{background:#ff000025;color:#ff4444;border:1px solid #ff000040}.high{background:#ff475725;color:#ff4757;border:1px solid #ff475740}.medium{background:#ffa50225;color:#ffa502;border:1px solid #ffa50240}.low{background:#00d4ff25;color:#00d4ff;border:1px solid #00d4ff40}.info{background:#3b82f625;color:#3b82f6;border:1px solid #3b82f640}table{width:100%;border-collapse:collapse;margin:1rem 0}th{background:#1a2332;color:#00ff88;text-align:left;padding:.6rem;font-size:.8rem}td{padding:.5rem .6rem;border-bottom:1px solid #ffffff08;font-size:.8rem}.meta{color:#94a3b8;font-size:.85rem;margin:.3rem 0}.sg{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin:1rem 0}.sc{background:#111827;border:1px solid #ffffff15;border-radius:8px;padding:1rem;text-align:center}.sv{font-size:2rem;font-weight:900}.sl{font-size:.75rem;color:#94a3b8}</style></head>
        <body><h1>🔒 CyberPulse — Penetration Test Report</h1>
        <p class="meta"><strong>Date:</strong> ${new Date().toLocaleString('vi-VN')}</p>
        <p class="meta"><strong>Duration:</strong> ${d.summary.duration}s</p>
        <h2>📊 Summary</h2>
        <div class="sg"><div class="sc"><div class="sv" style="color:#ff4444">${d.summary.critical}</div><div class="sl">Critical</div></div><div class="sc"><div class="sv" style="color:#ff4757">${d.summary.high}</div><div class="sl">High</div></div><div class="sc"><div class="sv" style="color:#ffa502">${d.summary.medium}</div><div class="sl">Medium</div></div><div class="sc"><div class="sv" style="color:#00d4ff">${d.summary.low}</div><div class="sl">Low</div></div><div class="sc"><div class="sv" style="color:#3b82f6">${d.summary.info}</div><div class="sl">Info</div></div></div>
        <h2>🔍 Findings</h2>
        <table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Module</th><th>Detail</th></tr></thead><tbody>
        ${d.findings.map((f,i)=>`<tr><td>${i+1}</td><td><span class="badge ${esc(f.severity||'info')}">${esc((f.severity||'info').toUpperCase())}</span></td><td>${esc(f.title||'')}</td><td>${esc(f.module||'—')}</td><td style="font-size:.75rem;color:#94a3b8">${esc(f.detail||'—')}</td></tr>`).join('')}
        </tbody></table>
        <div style="margin-top:3rem;border-top:1px solid #ffffff10;padding-top:1rem;text-align:center;color:#64748b;font-size:.75rem;">Generated by CyberPulse v3.1 Advanced Web Vulnerability Scanner</div></body></html>`;

        const blob=new Blob([html],{type:'text/html'});
        const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
        a.download=`cyberpulse-report-${Date.now()}.html`; a.click();
        toast('Báo cáo HTML đã tải!','success');
    },

    exportJSON(){
        const d=this._lastResults; if(!d){toast('Không có dữ liệu','warning');return;}
        const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
        const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
        a.download=`cyberpulse-data-${Date.now()}.json`; a.click();
        toast('JSON đã xuất!','success');
    }
};
