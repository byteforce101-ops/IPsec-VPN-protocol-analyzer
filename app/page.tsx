'use client'

import { useEffect, useState } from 'react'

type ActivePage = 'dashboard' | 'protocol' | 'ai_classifier' | 'findings' | 'samples' | 'reports'
type FilterSeverity = 'All' | 'Critical' | 'High' | 'Medium' | 'Low'

type Finding = {
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  title: string
  category: string
  explanation: string
  detected: string
  recommended: string
}

type AITrafficAnalysis = {
  predictedCategory?: string
  confidence?: number
  explanation?: string
  stats?: {
    espPacketCount: number
    avgPacketSizeBytes: number
    stdPacketSizeBytes: number
    maxPacketSizeBytes: number
    minPacketSizeBytes: number
  }
}

type IPsecParameters = {
  keyexchange?: string
  ike_version?: string
  ipsec_protocol?: string
  mode?: string
  auth_method?: string
  psk?: string | null
  aggressive_mode?: boolean
  pfs?: boolean
  dpd_delay?: string | null
  lifetime?: string | null
  dh_groups?: string[]
  ciphers?: string[]
  hashes?: string[]
  spi_list?: string[]
  ip_version?: string
  replay_window?: string
}

type ScanResult = {
  reportId: string
  scanName: string
  fileName: string
  analyzedAt: string
  score: number
  grade: string
  severityCounts: {
    Critical: number
    High: number
    Medium: number
    Low: number
  }
  aiSummary: string
  mode?: string
  parameters?: IPsecParameters
  aiTrafficAnalysis?: AITrafficAnalysis
  findings: Finding[]
  technicalDetails: string
}

const PRESET_SAMPLES = [
  {
    name: 'Secure IKEv2 Tunnel',
    filename: 'ikev2_aes256_pfs_secure.pcap',
    tag: '.pcap',
    desc: 'Tunnel Mode, AES-256-GCM, DH Group 19, PFS Enabled, Video Stream',
    badge: 'Grade A',
    badgeColor: 'text-[#10b981] bg-[#f0fdf4] border-[#bbf7d0]',
  },
  {
    name: 'Vulnerable IKEv1 Transport',
    filename: 'ikev1_3des_no_pfs_vulnerable.pcap',
    tag: '.pcap',
    desc: 'Transport Mode, 3DES, DH Group 2, Aggressive Mode, WhatsApp',
    badge: 'Grade F',
    badgeColor: 'text-[#ef4444] bg-[#fef2f2] border-[#fecaca]',
  },
  {
    name: 'IPv6 AH + ESP Tunnel',
    filename: 'ikev2_aes128_cbc_ah_esp_ipv6.pcap',
    tag: '.pcap',
    desc: 'IPv6, AH + ESP Protocols, AES-128-CBC, DH Group 14, ICMP',
    badge: 'Grade C',
    badgeColor: 'text-[#f59e0b] bg-[#fefce8] border-[#fef3c7]',
  },
  {
    name: 'IKEv2 Weak DH Group 2',
    filename: 'ikev2_weak_dh_group2.pcap',
    tag: '.pcap',
    desc: 'IKEv2, AES-256-CBC, DH Group 2 (1024-bit), VoIP Stream',
    badge: 'Grade F',
    badgeColor: 'text-[#ef4444] bg-[#fef2f2] border-[#fecaca]',
  },
  {
    name: 'strongSwan Secure NIST',
    filename: 'ipsec_strongswan_secure.conf',
    tag: '.conf',
    desc: 'NIST SP 800-77 compliant strongSwan configuration',
    badge: 'Grade A',
    badgeColor: 'text-[#10b981] bg-[#f0fdf4] border-[#bbf7d0]',
  },
  {
    name: 'strongSwan Vulnerable',
    filename: 'ipsec_strongswan_vulnerable.conf',
    tag: '.conf',
    desc: 'Vulnerable config — 3DES, IKEv1, Transport Mode',
    badge: 'Grade F',
    badgeColor: 'text-[#ef4444] bg-[#fef2f2] border-[#fecaca]',
  },
  {
    name: 'Cisco ASA Legacy IPsec',
    filename: 'cisco_vpn_legacy.cfg',
    tag: '.cfg',
    desc: 'Legacy Cisco ASA 3DES/SHA1 IPsec configuration',
    badge: 'Grade F',
    badgeColor: 'text-[#ef4444] bg-[#fef2f2] border-[#fecaca]',
  },
]

const NAV_ITEMS: { id: ActivePage; label: string; icon: string; desc: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '◈', desc: 'Upload & Audit' },
  { id: 'protocol', label: 'Protocol & SA Params', icon: '⬡', desc: 'IKE / ESP details' },
  { id: 'ai_classifier', label: 'AI Traffic Classifier', icon: '◉', desc: 'Encrypted flow ID' },
  { id: 'findings', label: 'Threat Matrix', icon: '⚑', desc: 'Vulnerability findings' },
  { id: 'samples', label: 'Testbed Samples', icon: '◫', desc: '7 VPN scenarios' },
  { id: 'reports', label: 'Export Reports', icon: '◳', desc: 'PDF reports' },
]

const scoreColor = (score: number) =>
  score >= 90 ? '#10b981' : score >= 65 ? '#5850ec' : score >= 45 ? '#f59e0b' : '#ef4444'

export default function AuraShieldVPNApp() {
  const [activePage, setActivePage] = useState<ActivePage>('dashboard')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [scanNameInput, setScanNameInput] = useState<string>('')
  const [isUploading, setIsUploading] = useState<boolean>(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [apiHealth, setApiHealth] = useState<'checking' | 'online' | 'offline'>('checking')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [severityFilter, setSeverityFilter] = useState<FilterSeverity>('All')
  const [showToast, setShowToast] = useState<boolean>(false)
  const [toastMessage, setToastMessage] = useState<string>('')
  const [dragOver, setDragOver] = useState(false)

  useEffect(() => {
    fetch('http://127.0.0.1:8000/')
      .then((res) => { if (res.ok) setApiHealth('online'); else setApiHealth('offline') })
      .catch(() => setApiHealth('offline'))
  }, [])

  const triggerToast = (msg: string) => {
    setToastMessage(msg)
    setShowToast(true)
    setTimeout(() => setShowToast(false), 3500)
  }

  const handleStartAnalysis = async (fileToUpload?: File) => {
    const file = fileToUpload || selectedFile
    if (!file) { setUploadError('Please select a valid .pcap, .pcapng, .conf, or .cfg file.'); return }
    setIsUploading(true)
    setUploadError(null)
    const formData = new FormData()
    formData.append('file', file)
    if (scanNameInput.trim()) formData.append('scanName', scanNameInput.trim())
    try {
      const response = await fetch('http://127.0.0.1:8000/api/analyze', { method: 'POST', body: formData })
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || `Backend error (HTTP ${response.status})`)
      }
      const data: ScanResult = await response.json()
      setScanResult(data)
      setIsUploading(false)
      triggerToast(`✓ Analysis Complete — ${data.score}/100 Score (${data.grade})`)
      setActivePage('findings')
    } catch (err: any) {
      setIsUploading(false)
      setUploadError(err.message || 'Cannot connect to backend. Run start_backend.bat first.')
    }
  }

  const handleLoadSample = async (filename: string) => {
    setIsUploading(true)
    setUploadError(null)
    try {
      const blob = new Blob([`# Sample: ${filename}`], { type: 'text/plain' })
      const sampleFile = new File([blob], filename, { type: 'text/plain' })
      const formData = new FormData()
      formData.append('file', sampleFile)
      formData.append('scanName', `Audit: ${filename}`)
      const response = await fetch('http://127.0.0.1:8000/api/analyze', { method: 'POST', body: formData })
      if (!response.ok) throw new Error('Sample analysis failed')
      const data: ScanResult = await response.json()
      setScanResult(data)
      setIsUploading(false)
      triggerToast(`✓ Sample Loaded — ${data.score}/100 Score (${data.grade})`)
      setActivePage('findings')
    } catch {
      setIsUploading(false)
      setUploadError('Backend offline. Run start_backend.bat on port 8000.')
    }
  }

  const filteredFindings = scanResult
    ? scanResult.findings.filter((f) => severityFilter === 'All' || f.severity === severityFilter)
    : []

  return (
    <div className="flex h-screen bg-[#f6f7fb] text-[#111827] font-sans overflow-hidden">
      {/* ═══════════════════════════════════════════════════
          SIDEBAR
      ═══════════════════════════════════════════════════ */}
      <aside
        className={`flex flex-col bg-white border-r border-[#edeef3] transition-all duration-300 shrink-0 ${
          sidebarCollapsed ? 'w-[64px]' : 'w-[240px]'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-3.5 h-16 border-b border-[#edeef3] shrink-0">
          <img
            src="/logo.jpg"
            alt="Cypher Lens Logo"
            className="w-10 h-10 rounded-xl object-cover shrink-0 shadow-sm border border-[#edeef3]"
          />
          {!sidebarCollapsed && (
            <div className="overflow-hidden">
              <span className="font-extrabold text-sm tracking-tight text-[#111827] block leading-tight">Cypher Lens</span>
              <span className="text-[10px] text-[#5850ec] font-semibold">VPN Protocol Analyzer</span>
            </div>
          )}
        </div>

        {/* Nav Items */}
        <nav className="flex-1 py-4 space-y-1 px-2 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const isActive = activePage === item.id
            const hasBadge = (item.id === 'findings' || item.id === 'protocol' || item.id === 'ai_classifier') && scanResult
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                title={sidebarCollapsed ? item.label : ''}
                className={`w-full flex items-center gap-3 rounded-xl px-3 py-2.5 transition text-left group ${
                  isActive
                    ? 'bg-[#eef2ff] text-[#5850ec]'
                    : 'text-[#6b7280] hover:bg-[#f9fafb] hover:text-[#111827]'
                }`}
              >
                <span className={`text-lg shrink-0 transition ${isActive ? 'text-[#5850ec]' : 'text-[#9ca3af] group-hover:text-[#5850ec]'}`}>
                  {item.icon}
                </span>
                {!sidebarCollapsed && (
                  <div className="min-w-0 flex-1">
                    <span className="block text-xs font-bold truncate">{item.label}</span>
                    <span className="block text-[10px] text-[#9ca3af] truncate">{item.desc}</span>
                  </div>
                )}
                {!sidebarCollapsed && hasBadge && (
                  <span className="w-2 h-2 rounded-full bg-[#10b981] shrink-0" />
                )}
              </button>
            )
          })}
        </nav>

        {/* Sidebar Footer — Collapse */}
        <div className="border-t border-[#edeef3] px-2 py-3 shrink-0">
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-[#9ca3af] hover:text-[#5850ec] hover:bg-[#eef2ff] transition text-xs font-semibold"
          >
            <span>{sidebarCollapsed ? '▶' : '◀'}</span>
            {!sidebarCollapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* ═══════════════════════════════════════════════════
          MAIN CONTENT AREA
      ═══════════════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* TOP HEADER BAR */}
        <header className="bg-white border-b border-[#edeef3] h-16 flex items-center px-6 justify-between shrink-0">
          <div>
            <h1 className="text-base font-extrabold text-[#111827] tracking-tight">
              {NAV_ITEMS.find((n) => n.id === activePage)?.label}
            </h1>
            <p className="text-[11px] text-[#9ca3af]">
              {activePage === 'dashboard' && 'Upload a .pcap or .conf file to run an IPsec security audit'}
              {activePage === 'protocol' && 'IKE version, ESP/AH protocol, encryption & SA attributes'}
              {activePage === 'ai_classifier' && 'AI-inferred application traffic inside encrypted ESP flows'}
              {activePage === 'findings' && 'NIST SP 800-77 compliance threat matrix & risk scoring'}
              {activePage === 'samples' && 'Pre-built VPN testbed generation scenarios'}
              {activePage === 'reports' && 'Download PDF executive security assessment reports'}
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="w-9 h-9 rounded-full bg-[#fed7aa] text-[#c2410c] flex items-center justify-center font-extrabold text-xs shadow-sm">
              AS
            </div>
          </div>
        </header>

        {/* PAGE CONTENT */}
        <main className="flex-1 overflow-y-auto p-8">

          {/* ─── PAGE: DASHBOARD (Upload) ─── */}
          {activePage === 'dashboard' && (
            <div className="max-w-2xl mx-auto space-y-6">
              {/* Empty-state hero */}
              {!scanResult && (
                <div className="text-center mb-8">
                  <div className="w-16 h-16 rounded-2xl bg-[#eef2ff] text-[#5850ec] border border-[#c7d2fe] flex items-center justify-center mx-auto mb-4">
                    <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <h2 className="text-2xl font-extrabold text-[#111827]">IPsec Security Auditor</h2>
                  <p className="text-sm text-[#6b7280] mt-2 max-w-md mx-auto">
                    Upload a Wireshark packet capture or router configuration file to get an automated
                    AI-driven IPsec VPN security assessment with NIST SP 800-77 compliance scoring.
                  </p>
                </div>
              )}

              {/* Upload Card */}
              <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-[#f1f3f9] flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-extrabold text-[#111827]">Upload File for Analysis</h3>
                    <p className="text-xs text-[#6b7280] mt-0.5">Supports .pcap, .pcapng, .conf, .cfg</p>
                  </div>
                  <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full border ${
                    apiHealth === 'online'
                      ? 'bg-[#f0fdf4] text-[#10b981] border-[#bbf7d0]'
                      : 'bg-[#fef2f2] text-[#ef4444] border-[#fecaca]'
                  }`}>
                    {apiHealth === 'online' ? '● API READY' : '● API OFFLINE'}
                  </span>
                </div>

                <div className="p-6 space-y-4">
                  {uploadError && (
                    <div className="p-3 rounded-xl bg-[#fef2f2] border border-[#fecaca] text-xs text-[#ef4444] flex items-start gap-2">
                      <span className="mt-0.5">⚠</span>
                      <span>{uploadError}</span>
                    </div>
                  )}

                  {/* Drop Zone */}
                  <label
                    className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer block transition ${
                      dragOver
                        ? 'border-[#5850ec] bg-[#eef2ff]'
                        : 'border-[#e5e7eb] hover:border-[#5850ec] hover:bg-[#f9fafb]'
                    }`}
                    onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => {
                      e.preventDefault()
                      setDragOver(false)
                      if (e.dataTransfer.files[0]) setSelectedFile(e.dataTransfer.files[0])
                    }}
                  >
                    <input
                      type="file"
                      accept=".pcap,.pcapng,.conf,.cfg,.txt"
                      className="hidden"
                      onChange={(e) => { if (e.target.files?.[0]) setSelectedFile(e.target.files[0]) }}
                    />
                    <div className="text-3xl mb-3">{selectedFile ? '📄' : '📁'}</div>
                    <p className="text-sm font-extrabold text-[#111827]">
                      {selectedFile ? selectedFile.name : 'Drop file here or click to browse'}
                    </p>
                    <p className="text-xs text-[#9ca3af] mt-1">
                      {selectedFile
                        ? `${(selectedFile.size / 1024).toFixed(1)} KB · Ready to analyze`
                        : 'Wireshark PCAPs · strongSwan · Libreswan · Cisco ASA configs'}
                    </p>
                  </label>

                  {/* Scan Name + Submit */}
                  <div className="flex items-center gap-3">
                    <input
                      type="text"
                      placeholder="Scan label (e.g. Enterprise Gateway — DC1)"
                      value={scanNameInput}
                      onChange={(e) => setScanNameInput(e.target.value)}
                      className="flex-1 bg-[#f9fafb] border border-[#e5e7eb] focus:border-[#5850ec] rounded-xl px-4 py-2.5 text-xs text-[#111827] outline-none transition"
                    />
                    <button
                      onClick={() => handleStartAnalysis()}
                      disabled={!selectedFile || isUploading}
                      className="px-6 py-2.5 bg-[#5850ec] hover:bg-[#4338ca] disabled:bg-[#e5e7eb] disabled:text-[#9ca3af] text-white font-bold text-xs rounded-xl transition shadow-sm shrink-0"
                    >
                      {isUploading ? (
                        <span className="flex items-center gap-2">
                          <span className="w-3 h-3 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                          Analyzing...
                        </span>
                      ) : 'Run Audit'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Post-scan quick-nav hints */}
              {scanResult && (
                <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-sm font-extrabold text-[#111827]">Audit Complete — Navigate Results</h4>
                    <span
                      className="text-xl font-extrabold font-mono"
                      style={{ color: scoreColor(scanResult.score) }}
                    >
                      {scanResult.score}/100
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { page: 'protocol' as ActivePage, label: 'Protocol Params', icon: '⬡', sub: `${scanResult.parameters?.ike_version || 'IKEv2'} · ${scanResult.mode || 'Tunnel'}` },
                      { page: 'ai_classifier' as ActivePage, label: 'AI Classifier', icon: '◉', sub: `${scanResult.aiTrafficAnalysis?.predictedCategory || 'N/A'}` },
                      { page: 'findings' as ActivePage, label: 'Threat Matrix', icon: '⚑', sub: `${scanResult.findings.length} findings` },
                    ].map((item) => (
                      <button
                        key={item.page}
                        onClick={() => setActivePage(item.page)}
                        className="p-3 rounded-xl border border-[#f1f3f9] hover:border-[#5850ec] hover:bg-[#eef2ff] text-left transition group"
                      >
                        <span className="text-lg block mb-1 group-hover:text-[#5850ec]">{item.icon}</span>
                        <span className="text-xs font-bold text-[#111827] block">{item.label}</span>
                        <span className="text-[11px] text-[#9ca3af] truncate block">{item.sub}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ─── PAGE: PROTOCOL & SA PARAMS ─── */}
          {activePage === 'protocol' && (
            <div className="max-w-4xl mx-auto space-y-6">
              {!scanResult ? (
                <EmptyState icon="⬡" title="No Scan Results Yet" desc="Run an audit from the Dashboard first to see protocol and SA parameters." onAction={() => setActivePage('dashboard')} actionLabel="Go to Dashboard" />
              ) : (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Phase 1 */}
                    <SectionCard title="Phase 1 — IKE Negotiation">
                      <ParamRow label="IKE Version" value={scanResult.parameters?.ike_version || 'IKEv2'} status={scanResult.parameters?.keyexchange === 'ikev2' ? 'ok' : 'warn'} />
                      <ParamRow label="Authentication Method" value={scanResult.parameters?.auth_method === 'public_key' ? 'X.509 Certificate / Public Key' : 'Pre-Shared Key (PSK)'} status={scanResult.parameters?.auth_method === 'public_key' ? 'ok' : 'critical'} />
                      <ParamRow label="Diffie-Hellman Group" value={scanResult.parameters?.dh_groups?.join(', ') || 'Group 19 (ECP256)'} status={scanResult.parameters?.dh_groups?.some(g => g.includes('Group 2') || g.includes('1024')) ? 'warn' : 'ok'} />
                      <ParamRow label="Aggressive Mode" value={scanResult.parameters?.aggressive_mode ? 'Enabled (Vulnerable)' : 'Disabled (Main Mode)'} status={scanResult.parameters?.aggressive_mode ? 'critical' : 'ok'} />
                    </SectionCard>

                    {/* Phase 2 */}
                    <SectionCard title="Phase 2 — IPsec SA Parameters">
                      <ParamRow label="IPsec Protocol" value={scanResult.parameters?.ipsec_protocol || 'ESP'} status="neutral" />
                      <ParamRow label="Operating Mode" value={scanResult.mode || 'Tunnel Mode'} status={scanResult.mode === 'Transport Mode' ? 'warn' : 'ok'} />
                      <ParamRow label="Encryption Ciphers" value={scanResult.parameters?.ciphers?.join(', ') || 'aes-256-gcm'} status={scanResult.parameters?.ciphers?.some(c => c.includes('3des') || c.includes('des')) ? 'warn' : 'ok'} />
                      <ParamRow label="Hash / Integrity" value={scanResult.parameters?.hashes?.join(', ') || 'hmac-sha256'} status="ok" />
                      <ParamRow label="Perfect Forward Secrecy" value={scanResult.parameters?.pfs ? 'Enabled' : 'Disabled'} status={scanResult.parameters?.pfs ? 'ok' : 'critical'} />
                    </SectionCard>
                  </div>

                  {/* SA Security Association Indices */}
                  <SectionCard title="Security Association Identifiers (SPI)">
                    <div className="grid grid-cols-2 gap-3">
                      {(scanResult.parameters?.spi_list || ['0x4A81F2C9', '0x9E41C890']).map((spi, i) => (
                        <div key={i} className="px-4 py-2.5 bg-[#f9fafb] rounded-xl border font-mono text-xs text-[#5850ec] font-bold">
                          SA-{i + 1}: {spi}
                        </div>
                      ))}
                    </div>
                  </SectionCard>

                  {/* Technical Snippet */}
                  {scanResult.technicalDetails && (
                    <SectionCard title="Extracted Configuration / Packet Proposal">
                      <pre className="bg-[#111827] text-[#e5e7eb] rounded-xl p-4 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {scanResult.technicalDetails}
                      </pre>
                    </SectionCard>
                  )}
                </>
              )}
            </div>
          )}

          {/* ─── PAGE: AI TRAFFIC CLASSIFIER ─── */}
          {activePage === 'ai_classifier' && (
            <div className="max-w-3xl mx-auto space-y-6">
              {!scanResult ? (
                <EmptyState icon="◉" title="No Classification Data" desc="Upload a .pcap file from the Dashboard to run AI encrypted traffic classification." onAction={() => setActivePage('dashboard')} actionLabel="Go to Dashboard" />
              ) : !scanResult.aiTrafficAnalysis?.predictedCategory ? (
                <EmptyState icon="◉" title="No ESP Flows Detected" desc="No ESP packet data was found in the uploaded file. Try a .pcap capture with encrypted traffic." onAction={() => setActivePage('dashboard')} actionLabel="Upload a PCAP" />
              ) : (
                <>
                  {/* Main classifier result */}
                  <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#5850ec]">🤖 Encrypted Flow Classification</span>
                        <h3 className="text-xl font-extrabold text-[#111827] mt-1">{scanResult.aiTrafficAnalysis.predictedCategory}</h3>
                        <p className="text-xs text-[#6b7280] mt-2 max-w-lg">{scanResult.aiTrafficAnalysis.explanation}</p>
                      </div>
                      <div className="text-right shrink-0 pl-4">
                        <span className="block text-[10px] text-[#9ca3af] uppercase font-bold">AI Confidence</span>
                        <span className="text-3xl font-extrabold font-mono text-[#10b981]">{scanResult.aiTrafficAnalysis.confidence}%</span>
                      </div>
                    </div>

                    {/* Confidence bar */}
                    <div className="w-full h-2 bg-[#f1f3f9] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-[#5850ec] to-[#10b981] transition-all"
                        style={{ width: `${scanResult.aiTrafficAnalysis.confidence}%` }}
                      />
                    </div>
                  </div>

                  {/* Flow Statistics */}
                  {scanResult.aiTrafficAnalysis.stats && (
                    <SectionCard title="ESP Flow Statistical Features">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        {[
                          { label: 'ESP Packet Count', value: scanResult.aiTrafficAnalysis.stats.espPacketCount, unit: 'pkts' },
                          { label: 'Mean Payload Size', value: scanResult.aiTrafficAnalysis.stats.avgPacketSizeBytes, unit: 'bytes' },
                          { label: 'Std Deviation', value: scanResult.aiTrafficAnalysis.stats.stdPacketSizeBytes, unit: 'bytes' },
                          { label: 'Max / Min Size', value: `${scanResult.aiTrafficAnalysis.stats.maxPacketSizeBytes} / ${scanResult.aiTrafficAnalysis.stats.minPacketSizeBytes}`, unit: 'bytes' },
                        ].map((stat) => (
                          <div key={stat.label} className="p-4 bg-[#f9fafb] rounded-xl border text-center">
                            <span className="block text-[10px] text-[#9ca3af] uppercase font-bold mb-1">{stat.label}</span>
                            <span className="text-lg font-extrabold text-[#111827]">{stat.value}</span>
                            <span className="text-[10px] text-[#9ca3af] ml-1">{stat.unit}</span>
                          </div>
                        ))}
                      </div>
                    </SectionCard>
                  )}
                </>
              )}
            </div>
          )}

          {/* ─── PAGE: THREAT MATRIX / FINDINGS ─── */}
          {activePage === 'findings' && (
            <div className="max-w-4xl mx-auto space-y-6">
              {!scanResult ? (
                <EmptyState icon="⚑" title="No Findings Yet" desc="Run an audit from the Dashboard to generate a vulnerability and compliance threat matrix." onAction={() => setActivePage('dashboard')} actionLabel="Go to Dashboard" />
              ) : (
                <>
                  {/* Score + Summary Card */}
                  <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-6">
                    <div className="flex flex-col sm:flex-row gap-6 items-start">
                      {/* Score ring */}
                      <div className="shrink-0 text-center">
                        <div
                          className="w-20 h-20 rounded-2xl flex items-center justify-center font-extrabold text-2xl text-white mx-auto shadow-lg"
                          style={{ backgroundColor: scoreColor(scanResult.score) }}
                        >
                          {scanResult.score}
                        </div>
                        <span className="block text-xs font-bold text-[#6b7280] mt-2">{scanResult.grade}</span>
                        <span className="block text-[10px] text-[#9ca3af]">/ 100</span>
                      </div>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-base font-extrabold text-[#111827]">{scanResult.scanName}</h3>
                          <span className="font-mono text-[11px] text-[#5850ec] bg-[#eef2ff] px-2 py-0.5 rounded-full">{scanResult.reportId}</span>
                        </div>
                        <p className="text-xs text-[#6b7280] mb-3">
                          File: <code className="font-mono text-[#111827] font-bold">{scanResult.fileName}</code> · {scanResult.analyzedAt}
                        </p>
                        <p className="text-xs text-[#374151] leading-relaxed">{scanResult.aiSummary}</p>
                      </div>

                      {/* Severity counts */}
                      <div className="grid grid-cols-2 gap-2 shrink-0">
                        {[
                          { label: 'Critical', count: scanResult.severityCounts.Critical, color: 'text-[#ef4444] bg-[#fef2f2] border-[#fecaca]' },
                          { label: 'High', count: scanResult.severityCounts.High, color: 'text-[#f97316] bg-[#fff7ed] border-[#ffedd5]' },
                          { label: 'Medium', count: scanResult.severityCounts.Medium, color: 'text-[#eab308] bg-[#fefce8] border-[#fef3c7]' },
                          { label: 'Low', count: scanResult.severityCounts.Low, color: 'text-[#3b82f6] bg-[#eff6ff] border-[#dbeafe]' },
                        ].map((s) => (
                          <div key={s.label} className={`px-3 py-2 rounded-xl border text-center ${s.color}`}>
                            <span className="block text-lg font-extrabold">{s.count}</span>
                            <span className="block text-[10px] font-bold">{s.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Filter Bar */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-[#6b7280]">Filter by severity:</span>
                    {(['All', 'Critical', 'High', 'Medium', 'Low'] as FilterSeverity[]).map((sev) => (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        className={`px-3 py-1.5 rounded-full text-xs font-bold transition border ${
                          severityFilter === sev
                            ? 'bg-[#5850ec] text-white border-[#5850ec]'
                            : 'bg-white text-[#6b7280] border-[#e5e7eb] hover:border-[#5850ec] hover:text-[#5850ec]'
                        }`}
                      >
                        {sev}
                        {sev !== 'All' && (
                          <span className="ml-1.5 opacity-70">
                            ({sev === 'Critical' ? scanResult.severityCounts.Critical
                              : sev === 'High' ? scanResult.severityCounts.High
                              : sev === 'Medium' ? scanResult.severityCounts.Medium
                              : scanResult.severityCounts.Low})
                          </span>
                        )}
                      </button>
                    ))}
                  </div>

                  {/* Findings List */}
                  <div className="space-y-3">
                    {filteredFindings.length === 0 ? (
                      <div className="bg-white rounded-2xl border border-[#e5e7eb] p-8 text-center text-[#9ca3af] text-sm">
                        No findings matching the selected filter.
                      </div>
                    ) : (
                      filteredFindings.map((f, i) => (
                        <div key={i} className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-5 space-y-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
                                f.severity === 'Critical' ? 'bg-[#fef2f2] text-[#ef4444] border-[#fecaca]'
                                : f.severity === 'High' ? 'bg-[#fff7ed] text-[#f97316] border-[#ffedd5]'
                                : f.severity === 'Medium' ? 'bg-[#fefce8] text-[#eab308] border-[#fef3c7]'
                                : 'bg-[#eff6ff] text-[#3b82f6] border-[#dbeafe]'
                              }`}>
                                {f.severity}
                              </span>
                              <span className="text-[11px] text-[#9ca3af] font-medium">{f.category}</span>
                            </div>
                            <code className="text-[11px] font-mono font-bold text-[#5850ec] bg-[#eef2ff] px-2 py-0.5 rounded">
                              {f.detected}
                            </code>
                          </div>
                          <h5 className="text-sm font-extrabold text-[#111827]">{f.title}</h5>
                          <p className="text-xs text-[#6b7280] leading-relaxed">{f.explanation}</p>
                          <div className="flex items-start gap-2 p-3 bg-[#f0fdf4] rounded-xl border border-[#bbf7d0]">
                            <span className="text-[#10b981] shrink-0">💡</span>
                            <p className="text-xs text-[#15803d] font-semibold leading-relaxed">
                              <strong>NIST Recommendation:</strong> {f.recommended}
                            </p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          {/* ─── PAGE: TESTBED SAMPLES ─── */}
          {activePage === 'samples' && (
            <div className="max-w-5xl mx-auto space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {PRESET_SAMPLES.map((sample, idx) => (
                  <div
                    key={idx}
                    className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-5 flex flex-col justify-between hover:border-[#5850ec] transition group"
                  >
                    <div className="mb-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[11px] font-bold text-[#9ca3af] font-mono">{sample.tag}</span>
                        <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full border ${sample.badgeColor}`}>
                          {sample.badge}
                        </span>
                      </div>
                      <h4 className="text-sm font-extrabold text-[#111827] group-hover:text-[#5850ec] transition">{sample.name}</h4>
                      <p className="text-xs text-[#6b7280] mt-1 leading-relaxed">{sample.desc}</p>
                    </div>
                    <button
                      onClick={() => handleLoadSample(sample.filename)}
                      disabled={isUploading}
                      className="w-full py-2 rounded-xl bg-[#5850ec] hover:bg-[#4338ca] disabled:bg-[#e5e7eb] text-white font-bold text-xs transition"
                    >
                      {isUploading ? 'Analyzing...' : 'Run Audit'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ─── PAGE: REPORTS ─── */}
          {activePage === 'reports' && (
            <div className="max-w-2xl mx-auto space-y-6">
              {!scanResult ? (
                <EmptyState icon="◳" title="No Reports Generated" desc="Complete an audit first to generate a downloadable PDF executive security report." onAction={() => setActivePage('dashboard')} actionLabel="Go to Dashboard" />
              ) : (
                <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm p-6 space-y-5">
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-extrabold text-[#111827]">Executive PDF Report</h3>
                    <span className={`text-xs font-extrabold px-3 py-1 rounded-full border ${
                      scanResult.score >= 80 ? 'bg-[#f0fdf4] text-[#10b981] border-[#bbf7d0]'
                        : scanResult.score >= 50 ? 'bg-[#fefce8] text-[#eab308] border-[#fef3c7]'
                        : 'bg-[#fef2f2] text-[#ef4444] border-[#fecaca]'
                    }`}>
                      {scanResult.grade} · {scanResult.score}/100
                    </span>
                  </div>

                  <div className="space-y-2 text-sm">
                    {[
                      { label: 'Report ID', value: scanResult.reportId },
                      { label: 'Target File', value: scanResult.fileName },
                      { label: 'Scan Name', value: scanResult.scanName },
                      { label: 'Generated On', value: scanResult.analyzedAt },
                      { label: 'Total Findings', value: `${scanResult.findings.length} vulnerability entries` },
                    ].map((row) => (
                      <div key={row.label} className="flex items-center justify-between py-2 border-b border-[#f1f3f9]">
                        <span className="text-xs text-[#6b7280] font-medium">{row.label}</span>
                        <span className="text-xs font-bold text-[#111827] font-mono">{row.value}</span>
                      </div>
                    ))}
                  </div>

                  <a
                    href={`http://127.0.0.1:8000/api/reports/${scanResult.reportId}.pdf`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full flex items-center justify-center gap-2 py-3 bg-[#5850ec] hover:bg-[#4338ca] text-white font-bold text-sm rounded-xl transition shadow-sm"
                  >
                    ↗ Download PDF Executive Report
                  </a>
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* TOAST */}
      {showToast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 px-6 py-3 rounded-full bg-[#111827] text-white text-xs font-bold shadow-2xl flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#10b981]" />
          {toastMessage}
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   HELPER COMPONENTS
═══════════════════════════════════════════════════ */

function EmptyState({
  icon, title, desc, onAction, actionLabel,
}: {
  icon: string; title: string; desc: string; onAction: () => void; actionLabel: string
}) {
  return (
    <div className="text-center py-20">
      <div className="text-5xl mb-4 text-[#c7d2fe]">{icon}</div>
      <h3 className="text-lg font-extrabold text-[#374151] mb-2">{title}</h3>
      <p className="text-sm text-[#9ca3af] max-w-sm mx-auto mb-6">{desc}</p>
      <button
        onClick={onAction}
        className="px-5 py-2.5 bg-[#5850ec] hover:bg-[#4338ca] text-white font-bold text-xs rounded-xl transition shadow-sm"
      >
        {actionLabel}
      </button>
    </div>
  )
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-2xl border border-[#e5e7eb] shadow-sm overflow-hidden">
      <div className="px-5 py-3.5 border-b border-[#f1f3f9] bg-[#f9fafb]">
        <h4 className="text-xs font-extrabold text-[#374151] uppercase tracking-wider">{title}</h4>
      </div>
      <div className="p-5 space-y-3">{children}</div>
    </div>
  )
}

function ParamRow({ label, value, status }: { label: string; value: string; status: 'ok' | 'warn' | 'critical' | 'neutral' }) {
  const statusDot = status === 'ok' ? 'bg-[#10b981]' : status === 'warn' ? 'bg-[#f59e0b]' : status === 'critical' ? 'bg-[#ef4444]' : 'bg-[#d1d5db]'
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-[#f9fafb] last:border-0">
      <div className="flex items-center gap-2 shrink-0">
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 mt-0.5 ${statusDot}`} />
        <span className="text-xs text-[#6b7280] font-medium">{label}</span>
      </div>
      <span className="text-xs font-bold text-[#111827] text-right font-mono">{value}</span>
    </div>
  )
}
