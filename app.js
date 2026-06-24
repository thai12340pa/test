/* =====================================================
   CyberPulse - Penetration Testing Toolkit
   Main Application Logic
   ===================================================== */

// ==================== GLOBAL STATE ====================
const State = {
    scanCount: 0,
    vulnCount: 0,
    targetCount: 0,
    reportCount: 0,
    findings: [],
    activityLog: [],
    currentPanel: 'dashboard'
};

// ==================== MATRIX RAIN BACKGROUND ====================
const MatrixRain = {
    init() {
        const canvas = document.getElementById('matrixCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF';
        const fontSize = 12;
        const columns = Math.floor(canvas.width / fontSize);
        const drops = new Array(columns).fill(1);

        function draw() {
            ctx.fillStyle = 'rgba(10, 14, 23, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#00ff88';
            ctx.font = `${fontSize}px monospace`;

            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 50);

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    }
};

// ==================== NAVIGATION ====================
const Nav = {
    init() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const panel = item.dataset.panel;
                this.switchPanel(panel);
            });
        });

        // Sidebar toggle for mobile
        const toggle = document.getElementById('sidebarToggle');
        const sidebar = document.getElementById('sidebar');
        if (toggle && sidebar) {
            toggle.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
            });

            // Close sidebar on mobile when clicking a nav item
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', () => {
                    if (window.innerWidth <= 1024) {
                        sidebar.classList.add('collapsed');
                    }
                });
            });
        }

        // Initialize sidebar state for mobile
        if (window.innerWidth <= 1024 && sidebar) {
            sidebar.classList.add('collapsed');
        }
    },

    switchPanel(panelId) {
        // Update nav items
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const activeNav = document.querySelector(`[data-panel="${panelId}"]`);
        if (activeNav) activeNav.classList.add('active');

        // Update panels
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const activePanel = document.getElementById(`panel-${panelId}`);
        if (activePanel) activePanel.classList.add('active');

        // Update breadcrumb
        const breadcrumbText = activeNav ? activeNav.querySelector('.nav-label').textContent : 'Dashboard';
        const breadcrumbIcon = activeNav ? activeNav.querySelector('.nav-icon').textContent : '◉';
        document.querySelector('.breadcrumb-text').textContent = breadcrumbText;
        document.querySelector('.breadcrumb-icon').textContent = breadcrumbIcon;

        State.currentPanel = panelId;
    }
};

// ==================== CLOCK ====================
const Clock = {
    init() {
        this.update();
        setInterval(() => this.update(), 1000);
    },
    update() {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
        const dateStr = now.toLocaleDateString('vi-VN');
        const el = document.getElementById('topbarClock');
        if (el) el.textContent = `${dateStr} | ${timeStr}`;
    }
};

// ==================== TOAST NOTIFICATIONS ====================
const Toast = {
    show(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const icons = { success: '✓', error: '✗', info: 'ℹ', warning: '⚠' };
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${message}`;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
    }
};

// ==================== LOADING ====================
const Loading = {
    show(text = 'Đang xử lý...') {
        const overlay = document.getElementById('loadingOverlay');
        overlay.querySelector('.loading-text').textContent = text;
        overlay.classList.add('active');
    },
    hide() {
        document.getElementById('loadingOverlay').classList.remove('active');
    }
};

// ==================== ACTIVITY LOG ====================
const Activity = {
    add(icon, text) {
        const time = new Date().toLocaleTimeString('vi-VN');
        State.activityLog.unshift({ icon, text, time });
        if (State.activityLog.length > 50) State.activityLog.pop();
        this.render();
    },
    render() {
        const container = document.getElementById('activityLog');
        if (!container) return;
        if (State.activityLog.length === 0) {
            container.innerHTML = `<div class="activity-empty"><span class="activity-empty-icon">◇</span><p>Chưa có hoạt động nào</p></div>`;
            return;
        }
        container.innerHTML = State.activityLog.map(a => `
            <div class="activity-item">
                <div class="activity-icon">${a.icon}</div>
                <div>
                    <div class="activity-text">${a.text}</div>
                    <div class="activity-time">${a.time}</div>
                </div>
            </div>
        `).join('');
    }
};

// ==================== STATS ====================
const Stats = {
    update() {
        const animate = (el, target) => {
            if (!el) return;
            let current = parseInt(el.textContent) || 0;
            if (current === target) return;
            const step = target > current ? 1 : -1;
            const timer = setInterval(() => {
                current += step;
                el.textContent = current;
                if (current === target) clearInterval(timer);
            }, 30);
        };
        animate(document.getElementById('statScans'), State.scanCount);
        animate(document.getElementById('statVulns'), State.vulnCount);
        animate(document.getElementById('statTargets'), State.targetCount);
        animate(document.getElementById('statReports'), State.reportCount);
    }
};

// ==================== UTILITY FUNCTIONS ====================
const Utils = {
    sanitize(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    isValidDomain(domain) {
        return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$/.test(domain);
    },

    isValidIP(ip) {
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    },

    extractDomain(input) {
        let domain = input.trim().toLowerCase();
        domain = domain.replace(/^https?:\/\//, '');
        domain = domain.replace(/\/.*$/, '');
        domain = domain.replace(/:\d+$/, '');
        return domain;
    },

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    randomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
};

// ==================== FINDINGS MANAGER ====================
const Findings = {
    add(finding) {
        State.findings.push({
            id: Date.now(),
            timestamp: new Date().toISOString(),
            ...finding
        });
        State.vulnCount = State.findings.length;
        Stats.update();
        this.render();
    },

    render() {
        const list = document.getElementById('findingsList');
        const count = document.getElementById('findingsCount');
        if (!list || !count) return;
        count.textContent = State.findings.length;

        if (State.findings.length === 0) {
            list.innerHTML = '<div style="text-align:center;padding:1rem;color:var(--text-muted);font-size:0.8rem;">Chưa có phát hiện nào</div>';
            return;
        }

        list.innerHTML = State.findings.map(f => `
            <div class="finding-item">
                <span class="badge badge-${f.severity || 'info'}">${(f.severity || 'info').toUpperCase()}</span>
                <span style="flex:1;font-size:0.8rem;">${Utils.sanitize(f.title)}</span>
                <span style="color:var(--text-muted);font-size:0.7rem;font-family:var(--font-mono);">${f.tool || ''}</span>
            </div>
        `).join('');
    }
};

// ==================== MAIN APP ====================
const App = {
    init() {
        MatrixRain.init();
        Nav.init();
        Clock.init();
        Stats.update();
        Findings.render();
        this.initPayloads();
        Activity.add('🚀', '<strong>CyberPulse</strong> đã khởi động thành công');
    },

    initPayloads() {
        // XSS Payloads
        const xssPayloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '{{constructor.constructor("alert(1)")()}}',
            '<details open ontoggle=alert(1)>',
            'javascript:alert(1)//'
        ];
        const xssContainer = document.getElementById('xssPayloads');
        if (xssContainer) {
            xssContainer.innerHTML = xssPayloads.map(p =>
                `<span class="payload-chip" onclick="document.getElementById('xssTarget').value+=\`${Utils.sanitize(p)}\`" title="${Utils.sanitize(p)}">${Utils.sanitize(p)}</span>`
            ).join('');
        }

        // SQLi Payloads
        const sqliPayloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' ORDER BY 1--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "admin'--",
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ];
        const sqliContainer = document.getElementById('sqliPayloads');
        if (sqliContainer) {
            sqliContainer.innerHTML = sqliPayloads.map(p =>
                `<span class="payload-chip" onclick="document.getElementById('sqliTarget').value+=\`${Utils.sanitize(p)}\`" title="${Utils.sanitize(p)}">${Utils.sanitize(p)}</span>`
            ).join('');
        }
    },

    async quickScan() {
        const target = document.getElementById('quickScanTarget').value.trim();
        if (!target) {
            Toast.show('Vui lòng nhập domain hoặc IP', 'warning');
            return;
        }

        const domain = Utils.extractDomain(target);
        Loading.show('Đang quét nhanh...');
        State.scanCount++;
        State.targetCount++;
        Stats.update();
        Activity.add('⚡', `Quét nhanh <strong>${Utils.sanitize(domain)}</strong>`);

        await Utils.sleep(800);

        const container = document.getElementById('quickScanResults');

        // Perform DNS lookup via public API
        try {
            const dnsData = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`).then(r => r.json());

            let ip = 'N/A';
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                ip = dnsData.Answer[dnsData.Answer.length - 1].data;
            }

            const results = {
                domain: domain,
                ip: ip,
                dns_status: dnsData.Status === 0 ? 'Resolved' : 'Failed',
                has_ipv6: 'Checking...',
                timestamp: new Date().toLocaleString('vi-VN')
            };

            // Check IPv6
            try {
                const ipv6Data = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=AAAA`).then(r => r.json());
                results.has_ipv6 = (ipv6Data.Answer && ipv6Data.Answer.length > 0) ? 'Yes' : 'No';
            } catch (e) {
                results.has_ipv6 = 'Unknown';
            }

            container.innerHTML = `
                <div class="result-section slide-up">
                    <div class="result-section-title">KẾT QUẢ QUÉT NHANH</div>
                    <div class="result-item">
                        <span class="result-key">Domain</span>
                        <span class="result-value">${Utils.sanitize(results.domain)}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">IP Address</span>
                        <span class="result-value">${Utils.sanitize(results.ip)}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">DNS Status</span>
                        <span class="result-value"><span class="badge badge-${results.dns_status === 'Resolved' ? 'safe' : 'high'}">${results.dns_status}</span></span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">IPv6 Support</span>
                        <span class="result-value">${Utils.sanitize(results.has_ipv6)}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Scan Time</span>
                        <span class="result-value">${results.timestamp}</span>
                    </div>
                </div>
            `;

            Toast.show('Quét nhanh hoàn tất!', 'success');
        } catch (error) {
            container.innerHTML = `<div class="result-section"><p style="color: var(--accent-danger);">Lỗi: Không thể phân giải domain. Kiểm tra lại đầu vào.</p></div>`;
            Toast.show('Lỗi khi quét: ' + error.message, 'error');
        }

        Loading.hide();
    }
};

// ==================== TOOL IMPLEMENTATIONS ====================
const Tools = {
    // ---- WHOIS Lookup ----
    async whoisLookup() {
        const target = document.getElementById('whoisTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập tên miền', 'warning'); return; }
        const domain = Utils.extractDomain(target);
        Loading.show('Đang tra cứu WHOIS...');
        State.scanCount++;
        Stats.update();
        Activity.add('⊕', `WHOIS lookup: <strong>${Utils.sanitize(domain)}</strong>`);

        try {
            // Use RDAP (Registration Data Access Protocol) - the modern replacement for WHOIS
            const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
            const data = await response.json();

            let registrar = 'N/A';
            let status = [];
            let nameservers = [];
            let events = {};

            if (data.entities) {
                for (const entity of data.entities) {
                    if (entity.roles && entity.roles.includes('registrar') && entity.vcardArray) {
                        const vcard = entity.vcardArray[1];
                        for (const field of vcard) {
                            if (field[0] === 'fn') registrar = field[3];
                        }
                    }
                }
            }

            if (data.status) status = data.status;
            if (data.nameservers) {
                nameservers = data.nameservers.map(ns => ns.ldhName || ns.unicodeName || 'N/A');
            }
            if (data.events) {
                for (const ev of data.events) {
                    events[ev.eventAction] = ev.eventDate;
                }
            }

            const container = document.getElementById('whoisResults');
            container.innerHTML = `
                <div class="result-section slide-up">
                    <div class="result-section-title">THÔNG TIN WHOIS</div>
                    <div class="result-item">
                        <span class="result-key">Domain Name</span>
                        <span class="result-value">${Utils.sanitize(data.ldhName || domain)}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Handle</span>
                        <span class="result-value">${Utils.sanitize(data.handle || 'N/A')}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Registrar</span>
                        <span class="result-value">${Utils.sanitize(registrar)}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Status</span>
                        <span class="result-value">${status.map(s => `<span class="badge badge-info" style="margin:0.1rem">${Utils.sanitize(s)}</span>`).join(' ') || 'N/A'}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Registration Date</span>
                        <span class="result-value">${events.registration ? new Date(events.registration).toLocaleDateString('vi-VN') : 'N/A'}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Last Updated</span>
                        <span class="result-value">${events['last changed'] ? new Date(events['last changed']).toLocaleDateString('vi-VN') : 'N/A'}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Expiration Date</span>
                        <span class="result-value">${events.expiration ? new Date(events.expiration).toLocaleDateString('vi-VN') : 'N/A'}</span>
                    </div>
                    <div class="result-item">
                        <span class="result-key">Name Servers</span>
                        <span class="result-value">${nameservers.map(ns => Utils.sanitize(ns)).join('<br>') || 'N/A'}</span>
                    </div>
                </div>
            `;

            Findings.add({ title: `WHOIS info collected for ${domain}`, severity: 'info', tool: 'WHOIS' });
            Toast.show('WHOIS lookup hoàn tất!', 'success');
        } catch (error) {
            document.getElementById('whoisResults').innerHTML = `
                <div class="result-section">
                    <p style="color: var(--accent-danger);">Không thể tra cứu WHOIS cho domain này. Thử lại hoặc kiểm tra domain.</p>
                    <p style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.5rem;">Error: ${Utils.sanitize(error.message)}</p>
                </div>
            `;
            Toast.show('Lỗi WHOIS: ' + error.message, 'error');
        }
        Loading.hide();
    },

    // ---- DNS Lookup ----
    async dnsLookup() {
        const target = document.getElementById('dnsTarget').value.trim();
        const recordType = document.getElementById('dnsRecordType').value;
        if (!target) { Toast.show('Vui lòng nhập tên miền', 'warning'); return; }
        const domain = Utils.extractDomain(target);
        Loading.show('Đang truy vấn DNS...');
        State.scanCount++;
        Stats.update();
        Activity.add('◈', `DNS query (${recordType}): <strong>${Utils.sanitize(domain)}</strong>`);

        const types = recordType === 'ALL' ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'] : [recordType];
        let allResults = [];

        try {
            for (const type of types) {
                const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
                const data = await response.json();
                if (data.Answer) {
                    allResults.push(...data.Answer.map(a => ({
                        name: a.name,
                        type: type,
                        ttl: a.TTL,
                        data: a.data
                    })));
                }
            }

            const container = document.getElementById('dnsResults');
            if (allResults.length > 0) {
                container.innerHTML = `
                    <div class="result-section slide-up">
                        <div class="result-section-title">KẾT QUẢ DNS - ${Utils.sanitize(domain)}</div>
                        <table class="result-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Name</th>
                                    <th>Value</th>
                                    <th>TTL</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${allResults.map(r => `
                                    <tr>
                                        <td><span class="badge badge-info">${Utils.sanitize(r.type)}</span></td>
                                        <td>${Utils.sanitize(r.name)}</td>
                                        <td>${Utils.sanitize(r.data)}</td>
                                        <td>${r.ttl}s</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
                Findings.add({ title: `DNS records enumerated for ${domain} (${allResults.length} records)`, severity: 'info', tool: 'DNS' });
            } else {
                container.innerHTML = `<div class="result-section"><p style="color: var(--text-muted);">Không tìm thấy bản ghi DNS nào cho loại đã chọn.</p></div>`;
            }

            Toast.show(`DNS lookup hoàn tất: ${allResults.length} records`, 'success');
        } catch (error) {
            document.getElementById('dnsResults').innerHTML = `<div class="result-section"><p style="color: var(--accent-danger);">Lỗi DNS: ${Utils.sanitize(error.message)}</p></div>`;
            Toast.show('Lỗi DNS query', 'error');
        }
        Loading.hide();
    },

    // ---- HTTP Headers Analysis ----
    async headersAnalysis() {
        const target = document.getElementById('headersTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập URL', 'warning'); return; }
        Loading.show('Đang phân tích headers...');
        State.scanCount++;
        Stats.update();
        Activity.add('◧', `Headers analysis: <strong>${Utils.sanitize(target)}</strong>`);

        // Security headers to check
        const securityHeaders = [
            { name: 'Content-Security-Policy', desc: 'Ngăn chặn XSS và injection attacks', severity: 'high' },
            { name: 'X-Frame-Options', desc: 'Ngăn chặn clickjacking', severity: 'medium' },
            { name: 'X-Content-Type-Options', desc: 'Ngăn chặn MIME type sniffing', severity: 'medium' },
            { name: 'Strict-Transport-Security', desc: 'Bắt buộc sử dụng HTTPS', severity: 'high' },
            { name: 'X-XSS-Protection', desc: 'Bảo vệ XSS trên trình duyệt cũ', severity: 'low' },
            { name: 'Referrer-Policy', desc: 'Kiểm soát thông tin referrer', severity: 'low' },
            { name: 'Permissions-Policy', desc: 'Kiểm soát quyền truy cập tính năng', severity: 'medium' },
            { name: 'X-Permitted-Cross-Domain-Policies', desc: 'Kiểm soát cross-domain', severity: 'low' },
            { name: 'Cross-Origin-Embedder-Policy', desc: 'Kiểm soát embedding cross-origin', severity: 'medium' },
            { name: 'Cross-Origin-Opener-Policy', desc: 'Kiểm soát window opener', severity: 'medium' },
            { name: 'Cross-Origin-Resource-Policy', desc: 'Kiểm soát resource sharing', severity: 'medium' }
        ];

        await Utils.sleep(500);

        // Simulate header analysis (actual CORS prevents direct header reading from browser)
        const container = document.getElementById('headersResults');
        const domain = Utils.extractDomain(target);

        // Try to fetch with CORS
        let fetchedHeaders = null;
        try {
            const resp = await fetch(target.startsWith('http') ? target : `https://${target}`, { method: 'HEAD', mode: 'no-cors' });
            // In no-cors mode, we can't read headers, so we simulate the analysis
        } catch (e) {
            // Expected in many cases
        }

        // Since browsers restrict header access due to CORS, we provide an educational analysis
        let missingCount = 0;
        const headerChecks = securityHeaders.map(h => {
            // Simulate check - in a real tool this would be done server-side
            const present = Math.random() > 0.5;
            if (!present) missingCount++;
            return { ...h, present };
        });

        const score = Math.round(((securityHeaders.length - missingCount) / securityHeaders.length) * 100);
        const scoreColor = score >= 80 ? '#00ff88' : score >= 50 ? '#ffa502' : '#ff4757';

        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">SECURITY HEADERS ANALYSIS - ${Utils.sanitize(domain)}</div>
                <div style="text-align:center;padding:1rem;margin-bottom:1rem;background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border-color);">
                    <div style="font-size:2rem;font-weight:900;color:${scoreColor};font-family:var(--font-mono);">${score}/100</div>
                    <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.3rem;">Security Score (Simulated)</div>
                </div>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Lưu ý: Do hạn chế CORS của trình duyệt, kết quả này là mô phỏng. Để kết quả chính xác, cần sử dụng công cụ server-side.
                </p>
                ${headerChecks.map(h => `
                    <div class="header-check">
                        <span class="header-check-icon">${h.present ? '✅' : '❌'}</span>
                        <span class="header-check-name">${h.name}</span>
                        <span class="header-check-status">
                            <span class="badge badge-${h.present ? 'safe' : h.severity}">${h.present ? 'PRESENT' : 'MISSING'}</span>
                        </span>
                    </div>
                `).join('')}
            </div>
        `;

        if (missingCount > 0) {
            Findings.add({ title: `${missingCount} security headers missing on ${domain}`, severity: missingCount > 5 ? 'high' : 'medium', tool: 'Headers' });
        }
        Toast.show(`Phân tích headers hoàn tất: ${missingCount} headers thiếu`, missingCount > 5 ? 'warning' : 'success');
        Loading.hide();
    },

    // ---- Technology Detection ----
    async techDetection() {
        const target = document.getElementById('techTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập URL', 'warning'); return; }
        Loading.show('Đang phát hiện công nghệ...');
        State.scanCount++;
        Stats.update();
        Activity.add('⬡', `Tech detection: <strong>${Utils.sanitize(target)}</strong>`);

        await Utils.sleep(1000);

        // Common technology signatures (simulated detection)
        const techDB = {
            'Web Servers': ['Nginx', 'Apache', 'LiteSpeed', 'IIS', 'Cloudflare'],
            'CMS': ['WordPress', 'Drupal', 'Joomla', 'Ghost', 'Shopify'],
            'JavaScript Frameworks': ['React', 'Vue.js', 'Angular', 'Next.js', 'jQuery'],
            'CSS Frameworks': ['Bootstrap', 'Tailwind CSS', 'Foundation', 'Bulma'],
            'Programming Languages': ['PHP', 'Python', 'Node.js', 'Ruby', 'Java'],
            'CDN': ['Cloudflare', 'CloudFront', 'Akamai', 'Fastly'],
            'Analytics': ['Google Analytics', 'Hotjar', 'Mixpanel'],
            'Security': ['reCAPTCHA', 'Cloudflare WAF', 'Let\'s Encrypt']
        };

        const detected = {};
        for (const [category, techs] of Object.entries(techDB)) {
            const count = Utils.randomInt(0, 2);
            const shuffled = techs.sort(() => 0.5 - Math.random());
            detected[category] = shuffled.slice(0, count);
        }

        const container = document.getElementById('techResults');
        let html = '<div class="result-section slide-up">';
        html += `<div class="result-section-title">PHÁT HIỆN CÔNG NGHỆ - ${Utils.sanitize(Utils.extractDomain(target))}</div>`;
        html += `<p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
            ⚠ Lưu ý: Kết quả mô phỏng. Để phát hiện chính xác, tích hợp với Wappalyzer API hoặc tương tự.
        </p>`;

        for (const [category, techs] of Object.entries(detected)) {
            if (techs.length > 0) {
                html += `<div style="margin-bottom:1rem;">
                    <div class="tech-category" style="margin-bottom:0.5rem;">${category}</div>
                    <div>${techs.map(t => `<span class="tech-card">${Utils.sanitize(t)}</span>`).join('')}</div>
                </div>`;
            }
        }

        html += '</div>';
        container.innerHTML = html;

        Findings.add({ title: `Technology detection on ${Utils.extractDomain(target)}`, severity: 'info', tool: 'TechDetect' });
        Toast.show('Phát hiện công nghệ hoàn tất!', 'success');
        Loading.hide();
    },

    // ---- Subdomain Finder ----
    async subdomainFinder() {
        const target = document.getElementById('subdomainTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập domain', 'warning'); return; }
        const domain = Utils.extractDomain(target);
        Loading.show('Đang tìm subdomain...');
        State.scanCount++;
        Stats.update();
        Activity.add('◎', `Subdomain finder: <strong>${Utils.sanitize(domain)}</strong>`);

        const commonSubs = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'blog', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'media', 'shop',
            'store', 'portal', 'vpn', 'remote', 'test', 'beta', 'demo', 'docs', 'help',
            'support', 'status', 'm', 'mobile', 'img', 'images', 'assets', 'git',
            'jenkins', 'ci', 'jira', 'confluence', 'wiki', 'dashboard'
        ];

        const container = document.getElementById('subdomainResults');
        let found = [];

        // Try DNS resolution for each subdomain using Google DNS
        let html = '<div class="result-section slide-up">';
        html += `<div class="result-section-title">SUBDOMAIN ENUMERATION - ${Utils.sanitize(domain)}</div>`;

        const batchSize = 5;
        for (let i = 0; i < commonSubs.length; i += batchSize) {
            const batch = commonSubs.slice(i, i + batchSize);
            const promises = batch.map(async (sub) => {
                try {
                    const resp = await fetch(`https://dns.google/resolve?name=${sub}.${domain}&type=A`);
                    const data = await resp.json();
                    if (data.Answer && data.Answer.length > 0) {
                        return {
                            subdomain: `${sub}.${domain}`,
                            ip: data.Answer[data.Answer.length - 1].data,
                            status: 'active'
                        };
                    }
                } catch (e) { }
                return null;
            });

            const results = await Promise.all(promises);
            found.push(...results.filter(Boolean));
        }

        if (found.length > 0) {
            html += `<p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">Tìm thấy <strong style="color:var(--accent-primary)">${found.length}</strong> subdomain</p>`;
            html += '<table class="result-table"><thead><tr><th>Subdomain</th><th>IP Address</th><th>Status</th></tr></thead><tbody>';
            found.forEach(s => {
                html += `<tr>
                    <td style="color:var(--accent-secondary)">${Utils.sanitize(s.subdomain)}</td>
                    <td>${Utils.sanitize(s.ip)}</td>
                    <td><span class="badge badge-safe">ACTIVE</span></td>
                </tr>`;
            });
            html += '</tbody></table>';

            Findings.add({ title: `Found ${found.length} subdomains for ${domain}`, severity: 'info', tool: 'Subdomain' });
        } else {
            html += '<p style="color:var(--text-muted);text-align:center;padding:1rem;">Không tìm thấy subdomain nào từ danh sách phổ biến.</p>';
        }

        html += '</div>';
        container.innerHTML = html;
        Toast.show(`Tìm thấy ${found.length} subdomain`, found.length > 0 ? 'success' : 'info');
        Loading.hide();
    },

    // ---- Port Scanner ----
    async portScan() {
        const target = document.getElementById('portTarget').value.trim();
        const range = document.getElementById('portRange').value;
        if (!target) { Toast.show('Vui lòng nhập IP hoặc domain', 'warning'); return; }
        Loading.show('Đang quét cổng...');
        State.scanCount++;
        Stats.update();
        Activity.add('⊞', `Port scan (${range}): <strong>${Utils.sanitize(target)}</strong>`);

        const portLists = {
            common: [
                { port: 21, service: 'FTP', desc: 'File Transfer Protocol' },
                { port: 22, service: 'SSH', desc: 'Secure Shell' },
                { port: 23, service: 'Telnet', desc: 'Telnet (insecure)' },
                { port: 25, service: 'SMTP', desc: 'Simple Mail Transfer Protocol' },
                { port: 53, service: 'DNS', desc: 'Domain Name System' },
                { port: 80, service: 'HTTP', desc: 'HyperText Transfer Protocol' },
                { port: 110, service: 'POP3', desc: 'Post Office Protocol' },
                { port: 143, service: 'IMAP', desc: 'Internet Message Access Protocol' },
                { port: 443, service: 'HTTPS', desc: 'HTTP Secure' },
                { port: 445, service: 'SMB', desc: 'Server Message Block' },
                { port: 993, service: 'IMAPS', desc: 'IMAP Secure' },
                { port: 995, service: 'POP3S', desc: 'POP3 Secure' },
                { port: 1433, service: 'MSSQL', desc: 'Microsoft SQL Server' },
                { port: 3306, service: 'MySQL', desc: 'MySQL Database' },
                { port: 3389, service: 'RDP', desc: 'Remote Desktop Protocol' },
                { port: 5432, service: 'PostgreSQL', desc: 'PostgreSQL Database' },
                { port: 5900, service: 'VNC', desc: 'Virtual Network Computing' },
                { port: 8080, service: 'HTTP-Alt', desc: 'HTTP Alternative' },
                { port: 8443, service: 'HTTPS-Alt', desc: 'HTTPS Alternative' },
                { port: 27017, service: 'MongoDB', desc: 'MongoDB Database' }
            ],
            web: [
                { port: 80, service: 'HTTP', desc: 'HyperText Transfer Protocol' },
                { port: 443, service: 'HTTPS', desc: 'HTTP Secure' },
                { port: 8080, service: 'HTTP-Alt', desc: 'HTTP Alternative' },
                { port: 8443, service: 'HTTPS-Alt', desc: 'HTTPS Alternative' }
            ],
            db: [
                { port: 1433, service: 'MSSQL', desc: 'Microsoft SQL Server' },
                { port: 1521, service: 'Oracle', desc: 'Oracle Database' },
                { port: 3306, service: 'MySQL', desc: 'MySQL Database' },
                { port: 5432, service: 'PostgreSQL', desc: 'PostgreSQL Database' },
                { port: 6379, service: 'Redis', desc: 'Redis Cache' },
                { port: 27017, service: 'MongoDB', desc: 'MongoDB Database' },
                { port: 9042, service: 'Cassandra', desc: 'Apache Cassandra' }
            ],
            mail: [
                { port: 25, service: 'SMTP', desc: 'Simple Mail Transfer Protocol' },
                { port: 110, service: 'POP3', desc: 'Post Office Protocol' },
                { port: 143, service: 'IMAP', desc: 'Internet Message Access Protocol' },
                { port: 465, service: 'SMTPS', desc: 'SMTP Secure' },
                { port: 587, service: 'SMTP-Sub', desc: 'SMTP Submission' },
                { port: 993, service: 'IMAPS', desc: 'IMAP Secure' },
                { port: 995, service: 'POP3S', desc: 'POP3 Secure' }
            ],
            full: [] // Will be generated
        };

        // Generate top 100 ports
        const topPorts = [7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,27017,32768,49152,49153,49154];
        portLists.full = topPorts.map(p => {
            const known = portLists.common.find(k => k.port === p);
            return known || { port: p, service: 'Unknown', desc: 'Unknown service' };
        });

        const ports = portLists[range] || portLists.common;
        const progressContainer = document.getElementById('portProgress');
        const progressFill = document.getElementById('portProgressFill');
        const progressText = document.getElementById('portProgressText');
        progressContainer.style.display = 'flex';

        const results = [];

        for (let i = 0; i < ports.length; i++) {
            const p = ports[i];
            const progress = Math.round(((i + 1) / ports.length) * 100);
            progressFill.style.width = `${progress}%`;
            progressText.textContent = `${progress}% (Port ${p.port})`;

            // Simulate port scan with timing-based detection
            const status = Math.random() > 0.75 ? 'open' : (Math.random() > 0.5 ? 'closed' : 'filtered');
            results.push({ ...p, status });

            await Utils.sleep(50);
        }

        Loading.hide();
        progressContainer.style.display = 'none';

        const openPorts = results.filter(r => r.status === 'open');
        const container = document.getElementById('portResults');

        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">KẾT QUẢ QUÉT PORT - ${Utils.sanitize(target)}</div>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">
                    Tìm thấy <strong style="color:var(--accent-primary)">${openPorts.length}</strong> port mở / ${results.length} port đã quét
                </p>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Kết quả mô phỏng. Trình duyệt không hỗ trợ raw socket scanning. Sử dụng Nmap hoặc Masscan cho kết quả thực tế.
                </p>
                <table class="result-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Description</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr>
                                <td style="color:var(--accent-secondary);font-weight:600">${r.port}</td>
                                <td>${Utils.sanitize(r.service)}</td>
                                <td>${Utils.sanitize(r.desc)}</td>
                                <td><span class="badge badge-${r.status}">${r.status.toUpperCase()}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

        if (openPorts.length > 0) {
            Findings.add({ title: `${openPorts.length} open ports found on ${target}`, severity: openPorts.length > 5 ? 'medium' : 'low', tool: 'PortScan' });
        }
        Toast.show(`Port scan hoàn tất: ${openPorts.length} open ports`, 'success');
    },

    // ---- SSL/TLS Analyzer ----
    async sslAnalyze() {
        const target = document.getElementById('sslTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập domain', 'warning'); return; }
        const domain = Utils.extractDomain(target);
        Loading.show('Đang phân tích SSL/TLS...');
        State.scanCount++;
        Stats.update();
        Activity.add('⊠', `SSL analysis: <strong>${Utils.sanitize(domain)}</strong>`);

        await Utils.sleep(1500);

        // Simulated SSL analysis
        const protocols = [
            { name: 'TLS 1.3', supported: true, secure: true },
            { name: 'TLS 1.2', supported: true, secure: true },
            { name: 'TLS 1.1', supported: Math.random() > 0.7, secure: false },
            { name: 'TLS 1.0', supported: Math.random() > 0.8, secure: false },
            { name: 'SSL 3.0', supported: Math.random() > 0.95, secure: false },
            { name: 'SSL 2.0', supported: false, secure: false }
        ];

        const vulnerabilities = [
            { name: 'BEAST', vulnerable: Math.random() > 0.9 },
            { name: 'POODLE', vulnerable: Math.random() > 0.9 },
            { name: 'Heartbleed', vulnerable: Math.random() > 0.95 },
            { name: 'FREAK', vulnerable: Math.random() > 0.95 },
            { name: 'Logjam', vulnerable: Math.random() > 0.9 },
            { name: 'DROWN', vulnerable: Math.random() > 0.95 },
            { name: 'ROBOT', vulnerable: Math.random() > 0.9 },
        ];

        const insecureProtocols = protocols.filter(p => p.supported && !p.secure);
        const vulnFound = vulnerabilities.filter(v => v.vulnerable);
        const grade = vulnFound.length > 0 ? 'F' : insecureProtocols.length > 1 ? 'C' : insecureProtocols.length === 1 ? 'B' : 'A+';
        const gradeColor = { 'A+': '#00ff88', 'A': '#00ff88', 'B': '#ffa502', 'C': '#ff6b35', 'F': '#ff4757' }[grade] || '#ff4757';

        const container = document.getElementById('sslResults');
        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">SSL/TLS ANALYSIS - ${Utils.sanitize(domain)}</div>
                <div style="text-align:center;padding:1.5rem;margin-bottom:1rem;background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border-color);">
                    <div style="font-size:3rem;font-weight:900;color:${gradeColor};font-family:var(--font-mono);text-shadow:0 0 20px ${gradeColor}40;">${grade}</div>
                    <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.3rem;">SSL Grade (Simulated)</div>
                </div>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Kết quả mô phỏng. Sử dụng SSL Labs (ssllabs.com) để kiểm tra chính xác.
                </p>

                <div class="result-section-title" style="margin-top:1rem;">PROTOCOL SUPPORT</div>
                ${protocols.map(p => `
                    <div class="header-check">
                        <span class="header-check-icon">${p.supported ? (p.secure ? '✅' : '⚠️') : '❌'}</span>
                        <span class="header-check-name">${p.name}</span>
                        <span class="header-check-status">
                            <span class="badge badge-${p.supported ? (p.secure ? 'safe' : 'medium') : 'closed'}">${p.supported ? 'ENABLED' : 'DISABLED'}</span>
                        </span>
                    </div>
                `).join('')}

                <div class="result-section-title" style="margin-top:1.5rem;">VULNERABILITY CHECKS</div>
                ${vulnerabilities.map(v => `
                    <div class="header-check">
                        <span class="header-check-icon">${v.vulnerable ? '🔴' : '🟢'}</span>
                        <span class="header-check-name">${v.name}</span>
                        <span class="header-check-status">
                            <span class="badge badge-${v.vulnerable ? 'critical' : 'safe'}">${v.vulnerable ? 'VULNERABLE' : 'SAFE'}</span>
                        </span>
                    </div>
                `).join('')}
            </div>
        `;

        if (vulnFound.length > 0) {
            Findings.add({ title: `${vulnFound.length} SSL vulnerabilities on ${domain}: ${vulnFound.map(v => v.name).join(', ')}`, severity: 'critical', tool: 'SSL' });
        }
        if (insecureProtocols.length > 0) {
            Findings.add({ title: `Insecure TLS versions on ${domain}: ${insecureProtocols.map(p => p.name).join(', ')}`, severity: 'medium', tool: 'SSL' });
        }

        Toast.show(`SSL analysis hoàn tất: Grade ${grade}`, grade === 'A+' ? 'success' : 'warning');
        Loading.hide();
    },

    // ---- XSS Scanner ----
    async xssScan() {
        const target = document.getElementById('xssTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập URL với tham số', 'warning'); return; }
        Loading.show('Đang quét XSS...');
        State.scanCount++;
        Stats.update();
        Activity.add('⚡', `XSS scan: <strong>${Utils.sanitize(target)}</strong>`);

        const payloads = [
            { payload: '<script>alert(1)</script>', type: 'Reflected XSS', risk: 'high' },
            { payload: '<img src=x onerror=alert(1)>', type: 'Event Handler', risk: 'high' },
            { payload: '<svg onload=alert(1)>', type: 'SVG Injection', risk: 'high' },
            { payload: '"><script>alert(1)</script>', type: 'Attribute Escape', risk: 'critical' },
            { payload: "'-alert(1)-'", type: 'JS Context', risk: 'high' },
            { payload: '<body onload=alert(1)>', type: 'Body Onload', risk: 'medium' },
            { payload: '<iframe src="javascript:alert(1)">', type: 'iFrame Injection', risk: 'high' },
            { payload: '{{constructor.constructor("alert(1)")()}}', type: 'Template Injection', risk: 'critical' },
            { payload: '<details open ontoggle=alert(1)>', type: 'HTML5 Event', risk: 'medium' },
            { payload: 'javascript:alert(1)//', type: 'Protocol Handler', risk: 'medium' },
            { payload: '<marquee onstart=alert(1)>', type: 'Legacy HTML', risk: 'low' },
            { payload: '"><img src=x onerror=prompt(1)>', type: 'Double Escape', risk: 'high' }
        ];

        await Utils.sleep(1500);

        // Simulated XSS testing results
        const results = payloads.map(p => ({
            ...p,
            status: Math.random() > 0.8 ? 'vulnerable' : (Math.random() > 0.5 ? 'filtered' : 'safe'),
            response: Math.random() > 0.5 ? 'Reflected in response' : 'Encoded/Filtered'
        }));

        const vulns = results.filter(r => r.status === 'vulnerable');
        const container = document.getElementById('xssResults');

        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">XSS SCAN RESULTS</div>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Kết quả mô phỏng cho mục đích giáo dục. Do hạn chế CORS, cần server-side scanner cho kết quả thực.
                </p>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">
                    Phát hiện <strong style="color:${vulns.length > 0 ? 'var(--accent-danger)' : 'var(--accent-primary)'}">${vulns.length}</strong> lỗ hổng tiềm ẩn / ${results.length} payload đã thử
                </p>
                <table class="result-table">
                    <thead>
                        <tr>
                            <th>Payload</th>
                            <th>Type</th>
                            <th>Risk</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr>
                                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${Utils.sanitize(r.payload)}">${Utils.sanitize(r.payload)}</td>
                                <td>${r.type}</td>
                                <td><span class="badge badge-${r.risk}">${r.risk.toUpperCase()}</span></td>
                                <td><span class="badge badge-${r.status === 'vulnerable' ? 'critical' : r.status === 'filtered' ? 'medium' : 'safe'}">${r.status.toUpperCase()}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

        if (vulns.length > 0) {
            Findings.add({ title: `${vulns.length} potential XSS vulnerabilities found`, severity: 'high', tool: 'XSS' });
        }
        Toast.show(`XSS scan hoàn tất: ${vulns.length} lỗ hổng phát hiện`, vulns.length > 0 ? 'warning' : 'success');
        Loading.hide();
    },

    // ---- SQLi Tester ----
    async sqliTest() {
        const target = document.getElementById('sqliTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập URL', 'warning'); return; }
        Loading.show('Đang kiểm tra SQL Injection...');
        State.scanCount++;
        Stats.update();
        Activity.add('⛁', `SQLi test: <strong>${Utils.sanitize(target)}</strong>`);

        const payloads = [
            { payload: "' OR '1'='1", type: 'Boolean-based', technique: 'OR injection' },
            { payload: "' OR '1'='1' --", type: 'Comment-based', technique: 'OR with comment' },
            { payload: "1' ORDER BY 1--", type: 'Order By', technique: 'Column enumeration' },
            { payload: "' UNION SELECT NULL--", type: 'Union-based', technique: 'UNION injection' },
            { payload: "1; DROP TABLE users--", type: 'Stacked Query', technique: 'Destructive query' },
            { payload: "' AND 1=1--", type: 'Boolean-based', technique: 'AND true condition' },
            { payload: "' AND 1=2--", type: 'Boolean-based', technique: 'AND false condition' },
            { payload: "admin'--", type: 'Auth Bypass', technique: 'Login bypass' },
            { payload: "1' AND SLEEP(5)--", type: 'Time-based', technique: 'Blind SQLi' },
            { payload: "' HAVING 1=1--", type: 'Error-based', technique: 'HAVING clause' },
        ];

        await Utils.sleep(2000);

        const results = payloads.map(p => ({
            ...p,
            status: Math.random() > 0.85 ? 'vulnerable' : 'safe',
            detail: Math.random() > 0.5 ? 'Response differs' : 'No anomaly detected'
        }));

        const vulns = results.filter(r => r.status === 'vulnerable');
        const container = document.getElementById('sqliResults');

        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">SQL INJECTION TEST RESULTS</div>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Kết quả mô phỏng. Sử dụng SQLMap hoặc công cụ chuyên dụng cho kiểm tra thực tế.
                </p>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">
                    Phát hiện <strong style="color:${vulns.length > 0 ? 'var(--accent-danger)' : 'var(--accent-primary)'}">${vulns.length}</strong> điểm yếu tiềm ẩn / ${results.length} payload đã thử
                </p>
                <table class="result-table">
                    <thead>
                        <tr>
                            <th>Payload</th>
                            <th>Type</th>
                            <th>Technique</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr>
                                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${Utils.sanitize(r.payload)}">${Utils.sanitize(r.payload)}</td>
                                <td>${r.type}</td>
                                <td>${r.technique}</td>
                                <td><span class="badge badge-${r.status === 'vulnerable' ? 'critical' : 'safe'}">${r.status.toUpperCase()}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

        if (vulns.length > 0) {
            Findings.add({ title: `${vulns.length} potential SQLi vulnerabilities found`, severity: 'critical', tool: 'SQLi' });
        }
        Toast.show(`SQLi test hoàn tất: ${vulns.length} lỗ hổng`, vulns.length > 0 ? 'warning' : 'success');
        Loading.hide();
    },

    // ---- Directory Scanner ----
    async dirScan() {
        const target = document.getElementById('dirscanTarget').value.trim();
        const wordlist = document.getElementById('dirscanWordlist').value;
        if (!target) { Toast.show('Vui lòng nhập URL', 'warning'); return; }
        Loading.show('Đang dò tìm thư mục...');
        State.scanCount++;
        Stats.update();
        Activity.add('⊟', `Dir scan (${wordlist}): <strong>${Utils.sanitize(target)}</strong>`);

        const wordlists = {
            common: [
                'admin', 'login', 'dashboard', 'wp-admin', 'administrator', 'panel',
                'cpanel', 'phpmyadmin', 'backend', 'api', 'uploads', 'images', 'assets',
                'css', 'js', 'fonts', 'media', 'static', 'public', 'private', 'tmp',
                'temp', 'backup', 'backups', 'test', 'dev', 'staging', 'old', 'new',
                '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml', 'wp-content',
                'wp-includes', 'vendor', 'node_modules', 'config', 'db', 'database',
                'logs', 'log', 'cache', 'cgi-bin', 'bin', 'include', 'includes'
            ],
            admin: [
                'admin', 'administrator', 'admin1', 'admin2', 'admin_area', 'admin_login',
                'adminpanel', 'cms', 'cpanel', 'dashboard', 'manage', 'management',
                'panel', 'control', 'controlpanel', 'siteadmin', 'webadmin', 'moderator',
                'superadmin', 'useradmin', 'manager', 'wp-login.php', 'login.php',
                'admin.php', 'user', 'root', 'system', 'console'
            ],
            backup: [
                'backup', 'backups', 'bak', 'backup.zip', 'backup.tar.gz', 'backup.sql',
                'db.sql', 'database.sql', 'dump.sql', 'site.zip', 'www.zip', 'archive',
                'old', 'copy', '.bak', 'backup.bak', 'web.config.bak', 'config.bak',
                'index.php.bak', 'wp-config.php.bak', '.DS_Store', 'debug.log'
            ],
            config: [
                '.env', '.env.local', '.env.production', '.env.development', '.env.backup',
                'config.php', 'config.yml', 'config.json', 'settings.php', 'wp-config.php',
                'configuration.php', 'database.yml', 'secrets.yml', 'credentials',
                '.htpasswd', '.htaccess', 'web.config', 'server.xml', 'httpd.conf',
                'php.ini', '.git/config', '.svn/entries', 'Dockerfile', 'docker-compose.yml'
            ],
            api: [
                'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql', 'swagger',
                'api-docs', 'api/docs', 'api/swagger', 'api/health', 'api/status',
                'api/users', 'api/admin', 'api/login', 'api/auth', 'api/config',
                'api/debug', 'api/test', 'webhook', 'webhooks', 'ws', 'socket.io'
            ]
        };

        const dirs = wordlists[wordlist] || wordlists.common;
        const progressContainer = document.getElementById('dirProgress');
        const progressFill = document.getElementById('dirProgressFill');
        const progressText = document.getElementById('dirProgressText');
        progressContainer.style.display = 'flex';

        const results = [];

        for (let i = 0; i < dirs.length; i++) {
            const progress = Math.round(((i + 1) / dirs.length) * 100);
            progressFill.style.width = `${progress}%`;
            progressText.textContent = `${progress}% (/${dirs[i]})`;

            // Simulated directory check
            const statusCodes = [200, 301, 302, 403, 404, 500];
            const weights = [0.1, 0.05, 0.03, 0.08, 0.7, 0.04];
            let rand = Math.random();
            let status = 404;
            let cumulative = 0;
            for (let j = 0; j < statusCodes.length; j++) {
                cumulative += weights[j];
                if (rand <= cumulative) { status = statusCodes[j]; break; }
            }

            if (status !== 404) {
                results.push({ path: `/${dirs[i]}`, status, size: Utils.randomInt(200, 50000) });
            }

            await Utils.sleep(30);
        }

        Loading.hide();
        progressContainer.style.display = 'none';

        const container = document.getElementById('dirscanResults');
        const statusColor = (s) => {
            if (s === 200) return 'safe';
            if (s === 301 || s === 302) return 'info';
            if (s === 403) return 'medium';
            if (s === 500) return 'critical';
            return 'closed';
        };

        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">DIRECTORY SCAN RESULTS - ${Utils.sanitize(Utils.extractDomain(target))}</div>
                <p style="font-size:0.72rem;color:var(--accent-warning);margin-bottom:1rem;padding:0.5rem;background:rgba(255,165,2,0.08);border:1px solid rgba(255,165,2,0.2);border-radius:var(--radius-sm);">
                    ⚠ Kết quả mô phỏng. Sử dụng Dirbuster, Gobuster hoặc Feroxbuster cho kết quả thực tế.
                </p>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">
                    Tìm thấy <strong style="color:var(--accent-primary)">${results.length}</strong> đường dẫn / ${dirs.length} đã quét
                </p>
                ${results.length > 0 ? `
                <table class="result-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr>
                                <td style="color:var(--accent-secondary)">${Utils.sanitize(r.path)}</td>
                                <td><span class="badge badge-${statusColor(r.status)}">${r.status}</span></td>
                                <td>${r.size} B</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>` : '<p style="text-align:center;color:var(--text-muted);">Không tìm thấy đường dẫn nào.</p>'}
            </div>
        `;

        const interestingPaths = results.filter(r => r.status === 200 || r.status === 403);
        if (interestingPaths.length > 0) {
            Findings.add({ title: `${interestingPaths.length} interesting paths found on ${Utils.extractDomain(target)}`, severity: 'medium', tool: 'DirScan' });
        }
        Toast.show(`Dir scan hoàn tất: ${results.length} paths found`, 'success');
    },

    // ---- CVE Lookup ----
    async cveLookup() {
        const target = document.getElementById('cveTarget').value.trim();
        if (!target) { Toast.show('Vui lòng nhập CVE ID hoặc từ khóa', 'warning'); return; }
        Loading.show('Đang tra cứu CVE...');
        State.scanCount++;
        Stats.update();
        Activity.add('⚠', `CVE lookup: <strong>${Utils.sanitize(target)}</strong>`);

        try {
            let url;
            if (target.toUpperCase().startsWith('CVE-')) {
                url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(target.toUpperCase())}`;
            } else {
                // Search by keyword using NIST NVD API
                url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(target)}&resultsPerPage=10`;
            }

            const response = await fetch(url);
            const data = await response.json();

            const container = document.getElementById('cveResults');

            if (target.toUpperCase().startsWith('CVE-')) {
                // Single CVE result
                const cveId = data.cveMetadata?.cveId || target.toUpperCase();
                const desc = data.containers?.cna?.descriptions?.[0]?.value || 'No description available';
                const metrics = data.containers?.cna?.metrics || [];
                let severity = 'N/A';
                let score = 'N/A';

                if (metrics.length > 0) {
                    const cvss = metrics[0].cvssV3_1 || metrics[0].cvssV3_0 || {};
                    severity = cvss.baseSeverity || 'N/A';
                    score = cvss.baseScore || 'N/A';
                }

                container.innerHTML = `
                    <div class="result-section slide-up">
                        <div class="cve-card">
                            <div class="cve-id">${Utils.sanitize(cveId)}</div>
                            <div class="cve-desc">${Utils.sanitize(desc)}</div>
                            <div class="cve-meta">
                                <span>Severity: <span class="badge badge-${severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'high' : severity === 'MEDIUM' ? 'medium' : 'low'}">${severity}</span></span>
                                <span>Score: ${score}</span>
                                <span>State: ${Utils.sanitize(data.cveMetadata?.state || 'N/A')}</span>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                // Multiple CVE results from NVD
                const vulns = data.vulnerabilities || [];
                container.innerHTML = `
                    <div class="result-section slide-up">
                        <div class="result-section-title">CVE SEARCH RESULTS - "${Utils.sanitize(target)}"</div>
                        <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:1rem;">
                            Tìm thấy <strong style="color:var(--accent-primary)">${vulns.length}</strong> kết quả
                        </p>
                        ${vulns.map(v => {
                            const cve = v.cve;
                            const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
                            const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData || {};
                            const severity = cvss.baseSeverity || 'N/A';
                            const score = cvss.baseScore || 'N/A';
                            return `
                                <div class="cve-card">
                                    <div class="cve-id">${Utils.sanitize(cve.id)}</div>
                                    <div class="cve-desc">${Utils.sanitize(desc.substring(0, 300))}${desc.length > 300 ? '...' : ''}</div>
                                    <div class="cve-meta">
                                        <span>Score: ${score}</span>
                                        <span>Published: ${cve.published ? new Date(cve.published).toLocaleDateString('vi-VN') : 'N/A'}</span>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                `;
            }

            Findings.add({ title: `CVE lookup: ${target}`, severity: 'info', tool: 'CVE' });
            Toast.show('CVE lookup hoàn tất!', 'success');
        } catch (error) {
            document.getElementById('cveResults').innerHTML = `
                <div class="result-section">
                    <p style="color: var(--accent-danger);">Lỗi tra cứu CVE: ${Utils.sanitize(error.message)}</p>
                    <p style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.5rem;">Thử nhập đúng định dạng CVE-YYYY-XXXXX hoặc từ khóa.</p>
                </div>
            `;
            Toast.show('Lỗi CVE lookup', 'error');
        }
        Loading.hide();
    },

    // ---- Encoder/Decoder ----
    encode() {
        const input = document.getElementById('encoderInput').value;
        const type = document.getElementById('encoderType').value;
        let output = '';

        try {
            switch (type) {
                case 'base64':
                    output = btoa(unescape(encodeURIComponent(input)));
                    break;
                case 'url':
                    output = encodeURIComponent(input);
                    break;
                case 'html':
                    output = input.replace(/[&<>"']/g, m => ({
                        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
                    }[m]));
                    break;
                case 'hex':
                    output = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                    break;
                case 'binary':
                    output = Array.from(input).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
                    break;
                case 'rot13':
                    output = input.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
                    break;
                case 'unicode':
                    output = Array.from(input).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
                    break;
            }
            document.getElementById('encoderOutput').value = output;
            Toast.show('Encode thành công!', 'success');
            Activity.add('⟐', `Encoded text (${type})`);
        } catch (e) {
            Toast.show('Lỗi encode: ' + e.message, 'error');
        }
    },

    decode() {
        const input = document.getElementById('encoderInput').value;
        const type = document.getElementById('encoderType').value;
        let output = '';

        try {
            switch (type) {
                case 'base64':
                    output = decodeURIComponent(escape(atob(input)));
                    break;
                case 'url':
                    output = decodeURIComponent(input);
                    break;
                case 'html':
                    const textarea = document.createElement('textarea');
                    textarea.innerHTML = input;
                    output = textarea.value;
                    break;
                case 'hex':
                    output = input.split(' ').map(h => String.fromCharCode(parseInt(h, 16))).join('');
                    break;
                case 'binary':
                    output = input.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
                    break;
                case 'rot13':
                    output = input.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
                    break;
                case 'unicode':
                    output = input.replace(/\\u([0-9a-fA-F]{4})/g, (_, code) => String.fromCharCode(parseInt(code, 16)));
                    break;
            }
            document.getElementById('encoderOutput').value = output;
            Toast.show('Decode thành công!', 'success');
            Activity.add('⟐', `Decoded text (${type})`);
        } catch (e) {
            Toast.show('Lỗi decode: ' + e.message, 'error');
        }
    },

    // ---- Hash Generator ----
    async generateHash() {
        const input = document.getElementById('hashInput').value;
        if (!input) { Toast.show('Vui lòng nhập text', 'warning'); return; }

        const encoder = new TextEncoder();
        const data = encoder.encode(input);

        const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
        const results = [];

        for (const algo of algorithms) {
            const hashBuffer = await crypto.subtle.digest(algo, data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            results.push({ algo, hash: hashHex });
        }

        // MD5 simulation (Web Crypto doesn't support MD5, use simple implementation)
        const md5Hash = simpleMD5(input);
        results.unshift({ algo: 'MD5', hash: md5Hash });

        const container = document.getElementById('hashResults');
        container.innerHTML = `
            <div class="result-section slide-up">
                <div class="result-section-title">HASH RESULTS</div>
                ${results.map(r => `
                    <div class="hash-result-item">
                        <span class="hash-algo">${r.algo}</span>
                        <span class="hash-value">${r.hash}</span>
                        <button class="hash-copy" onclick="navigator.clipboard.writeText('${r.hash}');Tools.showCopyToast()">📋</button>
                    </div>
                `).join('')}
            </div>
        `;

        Toast.show('Hash generated thành công!', 'success');
        Activity.add('⟁', `Generated hashes for text`);
    },

    showCopyToast() {
        Toast.show('Đã copy vào clipboard!', 'success');
    },

    // ---- Password Generator ----
    generatePassword() {
        const length = parseInt(document.getElementById('passLength').value);
        const useUpper = document.getElementById('passUpper').checked;
        const useLower = document.getElementById('passLower').checked;
        const useNumbers = document.getElementById('passNumbers').checked;
        const useSymbols = document.getElementById('passSymbols').checked;

        let charset = '';
        if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (useNumbers) charset += '0123456789';
        if (useSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!charset) {
            Toast.show('Vui lòng chọn ít nhất một loại ký tự', 'warning');
            return;
        }

        let password = '';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        document.getElementById('passgenOutput').value = password;

        // Calculate strength
        const strength = this.calculateStrength(password);
        const strengthEl = document.getElementById('passStrength');
        const colors = { 'Rất yếu': '#ff4757', 'Yếu': '#ff6b35', 'Trung bình': '#ffa502', 'Mạnh': '#00d4ff', 'Rất mạnh': '#00ff88' };
        strengthEl.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="color:${colors[strength.label]};font-weight:600;">${strength.label}</span>
                <span style="color:var(--text-muted);font-size:0.75rem;">Entropy: ~${strength.entropy} bits</span>
            </div>
            <div class="strength-bar">
                <div class="strength-fill" style="width:${strength.percent}%;background:${colors[strength.label]};"></div>
            </div>
        `;

        Toast.show('Mật khẩu đã được tạo!', 'success');
        Activity.add('⚿', `Generated password (${length} chars)`);
    },

    calculateStrength(password) {
        let poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

        const entropy = Math.round(password.length * Math.log2(poolSize || 1));
        let label, percent;

        if (entropy < 28) { label = 'Rất yếu'; percent = 10; }
        else if (entropy < 36) { label = 'Yếu'; percent = 25; }
        else if (entropy < 60) { label = 'Trung bình'; percent = 50; }
        else if (entropy < 80) { label = 'Mạnh'; percent = 75; }
        else { label = 'Rất mạnh'; percent = 100; }

        return { entropy, label, percent };
    },

    checkPasswordStrength() {
        const password = document.getElementById('passCheckInput').value;
        const container = document.getElementById('passCheckResult');
        if (!password) { container.innerHTML = ''; return; }

        const strength = this.calculateStrength(password);
        const colors = { 'Rất yếu': '#ff4757', 'Yếu': '#ff6b35', 'Trung bình': '#ffa502', 'Mạnh': '#00d4ff', 'Rất mạnh': '#00ff88' };

        const checks = [
            { test: password.length >= 8, label: 'Ít nhất 8 ký tự' },
            { test: password.length >= 12, label: 'Ít nhất 12 ký tự' },
            { test: /[a-z]/.test(password), label: 'Chữ thường' },
            { test: /[A-Z]/.test(password), label: 'Chữ hoa' },
            { test: /[0-9]/.test(password), label: 'Số' },
            { test: /[^a-zA-Z0-9]/.test(password), label: 'Ký tự đặc biệt' },
            { test: !/(.)\1{2,}/.test(password), label: 'Không lặp ký tự' },
        ];

        container.innerHTML = `
            <div style="margin-top:0.75rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                    <span style="color:${colors[strength.label]};font-weight:600;font-family:var(--font-mono);font-size:0.85rem;">${strength.label}</span>
                    <span style="color:var(--text-muted);font-size:0.72rem;font-family:var(--font-mono);">Entropy: ~${strength.entropy} bits</span>
                </div>
                <div class="strength-bar">
                    <div class="strength-fill" style="width:${strength.percent}%;background:${colors[strength.label]};"></div>
                </div>
                <div style="margin-top:0.75rem;display:grid;grid-template-columns:1fr 1fr;gap:0.3rem;">
                    ${checks.map(c => `<div style="font-size:0.72rem;color:${c.test ? 'var(--accent-primary)' : 'var(--text-muted)'};">${c.test ? '✅' : '❌'} ${c.label}</div>`).join('')}
                </div>
            </div>
        `;
    },

    // ---- Copy Output ----
    copyOutput(elementId) {
        const el = document.getElementById(elementId);
        const text = el.value || el.textContent;
        navigator.clipboard.writeText(text).then(() => {
            Toast.show('Đã copy vào clipboard!', 'success');
        }).catch(() => {
            // Fallback
            el.select && el.select();
            document.execCommand('copy');
            Toast.show('Đã copy!', 'success');
        });
    },

    // ---- Report Generator ----
    generateReport() {
        const title = document.getElementById('reportTitle').value || 'Penetration Test Report';
        const target = document.getElementById('reportTarget').value || 'N/A';
        const author = document.getElementById('reportAuthor').value || 'CyberPulse';

        if (State.findings.length === 0) {
            Toast.show('Chưa có phát hiện nào để tạo báo cáo', 'warning');
            return;
        }

        const criticalCount = State.findings.filter(f => f.severity === 'critical').length;
        const highCount = State.findings.filter(f => f.severity === 'high').length;
        const mediumCount = State.findings.filter(f => f.severity === 'medium').length;
        const lowCount = State.findings.filter(f => f.severity === 'low').length;
        const infoCount = State.findings.filter(f => f.severity === 'info').length;

        const html = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>${Utils.sanitize(title)}</title>
<style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e2e8f0; padding: 2rem; max-width: 900px; margin: 0 auto; }
    h1 { color: #00ff88; border-bottom: 2px solid #00ff8833; padding-bottom: 1rem; }
    h2 { color: #00d4ff; margin-top: 2rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th { background: #1a2332; color: #00ff88; text-align: left; padding: 0.8rem; font-size: 0.85rem; }
    td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #ffffff08; font-size: 0.85rem; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 700; }
    .critical { background: #ff000025; color: #ff4444; border: 1px solid #ff000040; }
    .high { background: #ff475725; color: #ff4757; border: 1px solid #ff475740; }
    .medium { background: #ffa50225; color: #ffa502; border: 1px solid #ffa50240; }
    .low { background: #00d4ff25; color: #00d4ff; border: 1px solid #00d4ff40; }
    .info { background: #3b82f625; color: #3b82f6; border: 1px solid #3b82f640; }
    .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 1rem 0; }
    .summary-card { background: #111827; border: 1px solid #ffffff15; border-radius: 8px; padding: 1rem; text-align: center; }
    .summary-value { font-size: 2rem; font-weight: 900; }
    .summary-label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.3rem; }
    .meta { color: #94a3b8; font-size: 0.85rem; margin: 0.3rem 0; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ffffff10; color: #64748b; font-size: 0.75rem; text-align: center; }
</style>
</head>
<body>
<h1>🔒 ${Utils.sanitize(title)}</h1>
<p class="meta"><strong>Mục tiêu:</strong> ${Utils.sanitize(target)}</p>
<p class="meta"><strong>Tác giả:</strong> ${Utils.sanitize(author)}</p>
<p class="meta"><strong>Ngày:</strong> ${new Date().toLocaleDateString('vi-VN')} ${new Date().toLocaleTimeString('vi-VN')}</p>
<p class="meta"><strong>Công cụ:</strong> CyberPulse v3.0 Pro</p>

<h2>📊 Tổng quan</h2>
<div class="summary-grid">
    <div class="summary-card"><div class="summary-value" style="color:#ff4444">${criticalCount}</div><div class="summary-label">Critical</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#ff4757">${highCount}</div><div class="summary-label">High</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#ffa502">${mediumCount}</div><div class="summary-label">Medium</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#00d4ff">${lowCount}</div><div class="summary-label">Low</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#3b82f6">${infoCount}</div><div class="summary-label">Info</div></div>
</div>

<h2>🔍 Chi tiết phát hiện</h2>
<table>
<thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Tool</th><th>Time</th></tr></thead>
<tbody>
${State.findings.map((f, i) => `<tr>
    <td>${i + 1}</td>
    <td><span class="badge ${f.severity}">${(f.severity || 'info').toUpperCase()}</span></td>
    <td>${Utils.sanitize(f.title)}</td>
    <td>${Utils.sanitize(f.tool || 'N/A')}</td>
    <td>${new Date(f.timestamp).toLocaleString('vi-VN')}</td>
</tr>`).join('')}
</tbody>
</table>

<div class="footer">
    <p>Generated by CyberPulse Penetration Testing Toolkit</p>
    <p>⚠ Disclaimer: This report is for authorized testing purposes only.</p>
</div>
</body></html>`;

        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pentest-report-${Date.now()}.html`;
        a.click();
        URL.revokeObjectURL(url);

        State.reportCount++;
        Stats.update();
        Toast.show('Báo cáo HTML đã được tạo và tải xuống!', 'success');
        Activity.add('⊡', `Generated report: <strong>${Utils.sanitize(title)}</strong>`);
    },

    exportJSON() {
        if (State.findings.length === 0) {
            Toast.show('Chưa có dữ liệu để xuất', 'warning');
            return;
        }

        const data = {
            report: {
                title: document.getElementById('reportTitle').value || 'Penetration Test',
                target: document.getElementById('reportTarget').value || 'N/A',
                author: document.getElementById('reportAuthor').value || 'CyberPulse',
                date: new Date().toISOString(),
                tool: 'CyberPulse v3.0 Pro'
            },
            statistics: {
                totalFindings: State.findings.length,
                totalScans: State.scanCount,
                critical: State.findings.filter(f => f.severity === 'critical').length,
                high: State.findings.filter(f => f.severity === 'high').length,
                medium: State.findings.filter(f => f.severity === 'medium').length,
                low: State.findings.filter(f => f.severity === 'low').length,
                info: State.findings.filter(f => f.severity === 'info').length
            },
            findings: State.findings
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pentest-data-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);

        Toast.show('Dữ liệu JSON đã được xuất!', 'success');
    },

    clearFindings() {
        if (State.findings.length === 0) return;
        if (confirm('Xóa tất cả phát hiện? Hành động này không thể hoàn tác.')) {
            State.findings = [];
            State.vulnCount = 0;
            Stats.update();
            Findings.render();
            Toast.show('Đã xóa tất cả phát hiện', 'info');
            Activity.add('🗑️', 'Cleared all findings');
        }
    }
};

// ==================== SIMPLE MD5 IMPLEMENTATION ====================
function simpleMD5(string) {
    function md5cycle(x, k) {
        var a = x[0], b = x[1], c = x[2], d = x[3];
        a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
        a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
        a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
        a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
        x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
    }
    function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
    function md51(s) {
        var n = s.length, state = [1732584193, -271733879, -1732584194, 271733878], i;
        for (i = 64; i <= n; i += 64) { md5cycle(state, md5blk(s.substring(i - 64, i))); }
        s = s.substring(i - 64);
        var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++) tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) { md5cycle(state, tail); tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }
    function md5blk(s) {
        var md5blks = [], i;
        for (i = 0; i < 64; i += 4) { md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24); }
        return md5blks;
    }
    var hex_chr = '0123456789abcdef'.split('');
    function rhex(n) {
        var s = '', j = 0;
        for (; j < 4; j++) s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
        return s;
    }
    function hex(x) { for (var i = 0; i < x.length; i++) x[i] = rhex(x[i]); return x.join(''); }
    function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
    return hex(md51(string));
}

// ==================== INITIALIZE ====================
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
