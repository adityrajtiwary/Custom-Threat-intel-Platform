import CountUp from './CountUp'
import Login from './Login'
import ChatBot from './ChatBot'
import { useState, useEffect } from 'react'
import {
  Shield, Activity, AlertTriangle, Bug, Users, FileText, LogOut,
  Repeat, ChevronRight, X, Search, ExternalLink, TrendingUp,
} from 'lucide-react'
import {
  getStats, getIOCs, getRecurring, getIOCDetail,
  getCVEs, getAPT, getArticles, getIOCTypeChart, getSeverityChart,
} from './api'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer,
} from 'recharts'

const CHART_COLORS = ['#2563eb', '#7c3aed', '#0891b2', '#ca8a04', '#dc2626', '#16a34a', '#ea580c', '#db2777']

function severityBadge(sev) {
  const map = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' }
  return map[sev] || 'badge-gray'
}

export default function App() {
  const [authed, setAuthed] = useState(!!localStorage.getItem('ti_token'))
  const [page, setPage] = useState('overview')

  if (!authed) return <Login onSuccess={() => setAuthed(true)} />

  const [detail, setDetail] = useState(null)   // IOC detail panel
  const [iocFilter, setIocFilter] = useState({})  // drill-down filter for IOC page

  const nav = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'iocs', label: 'IOCs', icon: Shield },
    { id: 'cves', label: 'CVEs', icon: Bug },
    { id: 'apt', label: 'APT Groups', icon: Users },
    { id: 'articles', label: 'Threat Feed', icon: FileText },
  ]

  // helper: jump to IOC page with a filter applied (drill-down from cards)
  function logout() {
    localStorage.removeItem('ti_token')
    window.location.reload()
  }

  function drillToIOCs(filter) {
    setIocFilter(filter)
    setPage('iocs')
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield size={22} color="#2563eb" />
          ThreatIntel
        </div>
        {nav.map(n => {
          const Icon = n.icon
          return (
            <div key={n.id}
              className={`nav-item ${page === n.id ? 'active' : ''}`}
              onClick={() => setPage(n.id)}>
              <Icon size={18} />
              {n.label}
            </div>
          )
        })}
        <div className="nav-item" onClick={logout}
          style={{ marginTop: 'auto', color: '#dc2626' }}>
          <LogOut size={18} />
          Logout
        </div>
      </aside>

      <main className="main">
        {page === 'overview' && <Overview drillToIOCs={drillToIOCs} setDetail={setDetail} setPage={setPage} />}
        {page === 'iocs' && <IOCsPage filter={iocFilter} setFilter={setIocFilter} setDetail={setDetail} />}
        {page === 'cves' && <CVEsPage />}
        {page === 'apt' && <APTPage />}
        {page === 'articles' && <ArticlesPage />}
      </main>

      {detail && <DetailPanel value={detail} onClose={() => setDetail(null)} />}
      <ChatBot />
    </div>
  )
}

/* ---------------- OVERVIEW ---------------- */
function Overview({ drillToIOCs, setDetail, setPage }) {
  const [stats, setStats] = useState(null)
  const [iocTypes, setIocTypes] = useState([])
  const [severity, setSeverity] = useState([])
  const [recurring, setRecurring] = useState([])

  useEffect(() => {
    getStats().then(setStats)
    getIOCTypeChart().then(setIocTypes)
    getSeverityChart().then(setSeverity)
    getRecurring().then(setRecurring)
  }, [])

  if (!stats) return <div className="loading">Loading dashboard…</div>

  const cards = [
    { label: 'Total IOCs', value: stats.total_iocs, icon: Shield, color: '#2563eb', bg: '#eff4ff', onClick: () => drillToIOCs({}) },
    { label: 'Active IOCs', value: stats.active_iocs, icon: Activity, color: '#16a34a', bg: '#f0fdf4', onClick: () => drillToIOCs({ active_only: true }) },
    { label: 'Recurring', value: stats.recurring_iocs, icon: Repeat, color: '#ea580c', bg: '#fff7ed', onClick: () => drillToIOCs({}) },
    { label: 'Critical CVEs', value: stats.critical_cves, icon: AlertTriangle, color: '#dc2626', bg: '#fef2f2', onClick: () => setPage('cves') },
    { label: 'Total CVEs', value: stats.total_cves, icon: Bug, color: '#7c3aed', bg: '#f5f3ff', onClick: () => setPage('cves') },
    { label: 'APT Groups', value: stats.apt_groups, icon: Users, color: '#0891b2', bg: '#ecfeff', onClick: () => setPage('apt') },
  ]

  return (
    <>
      <div className="page-title">Threat Intelligence Overview</div>
      <div className="page-sub">Live view across all sources · click any card to drill down</div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 24 }}>
        {cards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className="stat-card" style={{ cursor: "pointer", "--accent": c.color }} onClick={c.onClick}>
              <div className="stat-icon" style={{ background: c.bg }}>
                <Icon size={20} color={c.color} />
              </div>
              <div className="stat-value" style={{ color: c.color }}><CountUp end={c.value} /></div>
              <div className="stat-label">{c.label} <ChevronRight size={12} style={{ verticalAlign: 'middle' }} /></div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-2" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="section-title">IOC Types</div>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={iocTypes} dataKey="value" nameKey="name" cx="50%" cy="50%"
                innerRadius={55} outerRadius={90} paddingAngle={2}>
                {iocTypes.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
            {iocTypes.map((t, i) => (
              <span key={t.name} className="badge badge-gray" style={{ cursor: 'pointer' }}
                onClick={() => drillToIOCs({ ioc_type: t.name })}>
                <span style={{ width: 8, height: 8, borderRadius: 4, background: CHART_COLORS[i % CHART_COLORS.length], display: 'inline-block' }} />
                {t.name} · {t.value}
              </span>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="section-title">CVE Severity</div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={severity}>
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {severity.map((s, i) => {
                  const col = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#16a34a' }
                  return <Cell key={i} fill={col[s.name] || '#2563eb'} />
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="section-title"><AlertTriangle size={16} color="#dc2626" /> Risk Breakdown</div>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
          {[
            { label: 'HIGH', value: stats.risk_high || 0, color: '#dc2626', bg: '#fef2f2' },
            { label: 'MEDIUM', value: stats.risk_medium || 0, color: '#ea580c', bg: '#fff7ed' },
            { label: 'LOW', value: stats.risk_low || 0, color: '#16a34a', bg: '#f0fdf4' },
          ].map(r => (
            <div key={r.label} onClick={() => drillToIOCs({ risk: r.label })}
              style={{ cursor: 'pointer', padding: 16, borderRadius: 10, background: r.bg, textAlign: 'center' }}>
              <div style={{ fontSize: 26, fontWeight: 700, color: r.color }}>{r.value.toLocaleString()}</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: r.color, marginTop: 4 }}>{r.label} RISK</div>
            </div>
          ))}
        </div>
      </div>

      {recurring.length > 0 && (
        <div className="card">
          <div className="section-title">
            <Repeat size={16} color="#ea580c" /> Recurring IOCs — seen multiple times
          </div>
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Malware</th><th>Times Seen</th></tr></thead>
            <tbody>
              {recurring.map(r => (
                <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setDetail(r.value)}>
                  <td><span className="badge badge-blue">{r.ioc_type}</span></td>
                  <td className="mono">{r.value}</td>
                  <td>{r.malware || '—'}</td>
                  <td><span className="badge badge-high"><TrendingUp size={12} /> {r.times_seen}×</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

/* ---------------- IOCs PAGE ---------------- */
function IOCsPage({ filter, setFilter, setDetail }) {
  const [data, setData] = useState(null)
  const [search, setSearch] = useState('')

  useEffect(() => {
    getIOCs({ ...filter, search: search || undefined, limit: 100 }).then(setData)
  }, [filter, search])

  return (
    <>
      <div className="page-title">Indicators of Compromise</div>
      <div className="page-sub">
        {data ? `${data.total.toLocaleString()} indicators` : 'Loading…'}
        {Object.keys(filter).length > 0 && (
          <span className="badge badge-blue" style={{ marginLeft: 8, cursor: 'pointer' }} onClick={() => setFilter({})}>
            clear filters <X size={12} />
          </span>
        )}
      </div>

      <div className="filters">
        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: 10, top: 10, color: '#6b7688' }} />
          <input className="input" style={{ paddingLeft: 34 }} placeholder="Search IOC value…"
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <select className="select" value={filter.ioc_type || ''}
          onChange={e => setFilter({ ...filter, ioc_type: e.target.value || undefined })}>
          <option value="">All types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="md5">MD5</option>
          <option value="sha256">SHA256</option>
          <option value="sha1">SHA1</option>
        </select>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {!data ? <div className="loading">Loading…</div> : (
          <table>
            <thead><tr><th>Type</th><th>Value</th><th>Malware</th><th>Reason</th><th>Seen</th></tr></thead>
            <tbody>
              {data.data.map(i => (
                <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => setDetail(i.value)}>
                  <td><span className="badge badge-blue">{i.ioc_type}</span></td>
                  <td className="mono">{i.value}</td>
                  <td>{i.malware || '—'}</td>
                  <td style={{ maxWidth: 340, color: '#6b7688' }}>{(i.reason || '').slice(0, 80)}</td>
                  <td><span className="badge badge-gray">{i.times_seen}×</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

/* ---------------- CVEs PAGE ---------------- */
function CVEsPage() {
  const [data, setData] = useState(null)
  const [sev, setSev] = useState('')
  const [kevOnly, setKevOnly] = useState(false)

  useEffect(() => {
    getCVEs({ severity: sev || undefined, kev_only: kevOnly, limit: 100 }).then(setData)
  }, [sev, kevOnly])

  return (
    <>
      <div className="page-title">Vulnerabilities (CVEs)</div>
      <div className="page-sub">{data ? `${data.total.toLocaleString()} CVEs` : 'Loading…'} · KEV = actively exploited</div>

      <div className="filters">
        <select className="select" value={sev} onChange={e => setSev(e.target.value)}>
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <label className="badge badge-gray" style={{ cursor: 'pointer', padding: '8px 12px' }}>
          <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} />
          &nbsp;Actively exploited only
        </label>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {!data ? <div className="loading">Loading…</div> : (
          <table>
            <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Status</th><th>Description</th></tr></thead>
            <tbody>
              {data.data.map(c => (
                <tr key={c.cve_id}>
                  <td className="mono" style={{ fontWeight: 600 }}>{c.cve_id}</td>
                  <td style={{ fontWeight: 600 }}>{c.cvss_score ?? '—'}</td>
                  <td><span className={`badge ${severityBadge(c.severity)}`}>{c.severity || '—'}</span></td>
                  <td>{c.kev_listed && <span className="badge badge-critical">KEV</span>}</td>
                  <td style={{ maxWidth: 380, color: '#6b7688' }}>{(c.description || '').slice(0, 90)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

/* ---------------- APT PAGE ---------------- */
function APTPage() {
  const [data, setData] = useState(null)
  useEffect(() => { getAPT().then(setData) }, [])
  if (!data) return <div className="loading">Loading…</div>

  return (
    <>
      <div className="page-title">APT Groups</div>
      <div className="page-sub">Threat actors extracted from intel articles</div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        {data.map(g => (
          <div key={g.id} className="stat-card" style={{ cursor: 'pointer' }}
            onClick={() => window.__sendPrompt?.(`Tell me about the ${g.name} APT group`)}>
            <div className="stat-icon" style={{ background: '#ecfeff' }}>
              <Users size={20} color="#0891b2" />
            </div>
            <div style={{ fontSize: 18, fontWeight: 700 }}>{g.name}</div>
            <div className="stat-label">Seen {g.times_seen}× · click for details</div>
          </div>
        ))}
      </div>
    </>
  )
}

/* ---------------- ARTICLES PAGE ---------------- */
function ArticlesPage() {
  const [data, setData] = useState(null)
  useEffect(() => { getArticles().then(setData) }, [])
  if (!data) return <div className="loading">Loading…</div>

  return (
    <>
      <div className="page-title">Threat Feed</div>
      <div className="page-sub">Latest intel articles with extracted actors & malware</div>
      <div className="grid" style={{ gridTemplateColumns: '1fr' }}>
        {data.map((a, i) => (
          <div key={i} className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 15 }}>{a.title}</div>
              {a.link && <a href={a.link} target="_blank" rel="noreferrer"><ExternalLink size={16} color="#6b7688" /></a>}
            </div>
            {a.summary && <div style={{ color: '#6b7688', marginTop: 8 }}>{a.summary}</div>}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 12 }}>
              {(a.apt_groups || []).map(g => <span key={g} className="badge badge-critical">{g}</span>)}
              {(a.malware || []).map(m => <span key={m} className="badge badge-high">{m}</span>)}
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

/* ---------------- DETAIL PANEL (drill-down) ---------------- */
function DetailPanel({ value, onClose }) {
  const [d, setD] = useState(null)
  useEffect(() => { getIOCDetail(value).then(setD) }, [value])

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, width: 440, height: '100vh',
      background: '#fff', borderLeft: '1px solid #e4e8ee', boxShadow: '-4px 0 24px rgba(16,24,40,0.08)',
      padding: 24, overflowY: 'auto', zIndex: 100,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>IOC Detail</div>
        <X size={20} style={{ cursor: 'pointer' }} onClick={onClose} />
      </div>
      {!d || d.error ? <div className="loading">Loading…</div> : (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="mono" style={{ fontSize: 15, fontWeight: 600, wordBreak: 'break-all' }}>{d.ioc.value}</div>
            <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              <span className="badge badge-blue">{d.ioc.ioc_type}</span>
              {d.ioc.is_active && <span className="badge badge-low">active</span>}
              <span className="badge badge-gray">seen {d.ioc.times_seen}×</span>
            </div>
          </div>

          <DetailRow label="Malware" value={d.ioc.malware} />
          <DetailRow label="Threat Type" value={d.ioc.threat_type} />
          <DetailRow label="Confidence" value={d.ioc.confidence != null ? `${d.ioc.confidence}%` : null} />
          <DetailRow label="First Seen" value={d.ioc.first_seen?.slice(0, 19).replace('T', ' ')} />
          <DetailRow label="Last Seen" value={d.ioc.last_seen?.slice(0, 19).replace('T', ' ')} />

          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, color: '#6b7688', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Why flagged</div>
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>{d.ioc.reason || '—'}</div>
          </div>

          {d.enrichment && (
            <>
              <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Enrichment</div>
              {d.enrichment.abuse_score != null && (
                <DetailRow label="Abuse Score" value={
                  <span className={"badge " + (d.enrichment.abuse_score >= 50 ? "badge-critical" : d.enrichment.abuse_score >= 15 ? "badge-high" : "badge-low")}>
                    {d.enrichment.abuse_score}% ({d.enrichment.abuse_reports || 0} reports)
                  </span>
                } />
              )}
              <DetailRow label="Country" value={d.enrichment.abuse_country} />
              <DetailRow label="ISP" value={d.enrichment.abuse_isp} />
              <DetailRow label="Usage" value={d.enrichment.abuse_usage} />
              {d.enrichment.shodan_ports && d.enrichment.shodan_ports !== 'none' && (
                <DetailRow label="Open Ports" value={
                  <span className="mono" style={{ fontSize: 12 }}>{d.enrichment.shodan_ports}</span>
                } />
              )}
              <DetailRow label="Shodan Org" value={d.enrichment.shodan_org && d.enrichment.shodan_org !== 'none' ? d.enrichment.shodan_org : null} />
            </>
          )}

          <div className="section-title" style={{ marginTop: 24, fontSize: 14 }}>Sighting History</div>
          {d.sightings.map((s, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f1f3f7' }}>
              <span className="badge badge-gray">{s.source}</span>
              <span style={{ fontSize: 12, color: '#6b7688' }}>{s.seen_at?.slice(0, 19).replace('T', ' ')}</span>
            </div>
          ))}
        </>
      )}
    </div>
  )
}

function DetailRow({ label, value }) {
  if (!value) return null
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f1f3f7' }}>
      <span style={{ fontSize: 13, color: '#6b7688' }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right' }}>{value}</span>
    </div>
  )
}
