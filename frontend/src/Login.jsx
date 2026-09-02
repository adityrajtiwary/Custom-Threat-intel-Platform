import { useState, useEffect, useRef } from 'react'
import { Shield, Lock, Terminal } from 'lucide-react'
import { login } from './api'

/* ---------- Animated cyber background (canvas) ---------- */
function CyberBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let w, h, nodes, animId

    function resize() {
      w = canvas.width = window.innerWidth
      h = canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    // network nodes
    const NODE_COUNT = Math.min(70, Math.floor(w / 22))
    nodes = Array.from({ length: NODE_COUNT }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      r: Math.random() * 2 + 1,
    }))

    function draw() {
      ctx.clearRect(0, 0, w, h)

      // move + draw nodes
      nodes.forEach((n) => {
        n.x += n.vx; n.y += n.vy
        if (n.x < 0 || n.x > w) n.vx *= -1
        if (n.y < 0 || n.y > h) n.vy *= -1
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
        ctx.fillStyle = 'rgba(59,130,246,0.7)'
        ctx.fill()
      })

      // connect nearby nodes (lines)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < 130) {
            ctx.beginPath()
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.strokeStyle = `rgba(59,130,246,${0.15 * (1 - dist / 130)})`
            ctx.lineWidth = 1
            ctx.stroke()
          }
        }
      }
      animId = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return <canvas ref={canvasRef} style={{
    position: 'fixed', inset: 0, zIndex: 0,
  }} />
}

/* ---------- Scrolling threat log strip ---------- */
function ThreatTicker() {
  const feed = [
    'THREAT DETECTED · Cobalt Strike C2 · 45.192.x.x',
    'IOC INGESTED · SHA256 · Vidar stealer',
    'CVE-2026-21962 · CVSS 9.8 · ACTIVELY EXPLOITED',
    'APT28 · HOOKEDGE backdoor · EU targets',
    'RANSOMWARE · Akira · new victim disclosed',
    'BianLian · 191 malicious IPs flagged',
    'ThreatFox · 1,371 new indicators',
    'CISA KEV · 6 vulnerabilities added',
  ]
  return (
    <div style={{
      position: 'absolute', bottom: 24, left: 0, right: 0, zIndex: 1,
      overflow: 'hidden', whiteSpace: 'nowrap', opacity: 0.5,
      fontFamily: 'monospace', fontSize: 12, color: '#3b82f6',
    }}>
      <div style={{ display: 'inline-block', animation: 'ticker 30s linear infinite' }}>
        {feed.concat(feed).map((f, i) => (
          <span key={i} style={{ marginRight: 40 }}>▸ {f}</span>
        ))}
      </div>
    </div>
  )
}

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleLogin(e) {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const { token } = await login(username, password, otp)
      localStorage.setItem('ti_token', token)
      window.location.reload()
    } catch (err) {
      setError('ACCESS DENIED — invalid credentials or OTP')
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', position: 'relative', overflow: 'hidden',
      background: 'radial-gradient(circle at 50% 40%, #0f1b33 0%, #060a14 100%)',
    }}>
      <style>{`
        @keyframes ticker { from { transform: translateX(0) } to { transform: translateX(-50%) } }
        @keyframes scanline {
          0% { transform: translateY(-100%) } 100% { transform: translateY(100%) }
        }
        @keyframes pulse-ring {
          0% { box-shadow: 0 0 0 0 rgba(59,130,246,0.4) }
          70% { box-shadow: 0 0 0 18px rgba(59,130,246,0) }
          100% { box-shadow: 0 0 0 0 rgba(59,130,246,0) }
        }
        @keyframes glow {
          0%,100% { opacity: 0.6 } 50% { opacity: 1 }
        }
        .login-input::placeholder { color: #5b6b85 }
        .login-input:focus { border-color: #3b82f6 !important; box-shadow: 0 0 0 3px rgba(59,130,246,0.15) }
      `}</style>

      <CyberBackground />
      <ThreatTicker />

      {/* scan line overlay */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none',
        background: 'linear-gradient(rgba(59,130,246,0.06), transparent 8%)',
        height: '100%', animation: 'scanline 6s linear infinite', opacity: 0.5,
      }} />

      {/* login card -- glassmorphism */}
      <div style={{
        position: 'relative', zIndex: 2, width: 380, padding: 36,
        background: 'rgba(13,22,41,0.72)', backdropFilter: 'blur(14px)',
        border: '1px solid rgba(59,130,246,0.25)', borderRadius: 16,
        boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            width: 60, height: 60, borderRadius: 16, margin: '0 auto 16px',
            background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            animation: 'pulse-ring 2.5s infinite',
          }}>
            <Shield size={28} color="#3b82f6" />
          </div>
          <div style={{
            fontSize: 22, fontWeight: 700, color: '#e8eefc', letterSpacing: 1,
          }}>THREAT<span style={{ color: '#3b82f6' }}>INTEL</span></div>
          <div style={{
            color: '#7d8ba8', fontSize: 12, marginTop: 6, fontFamily: 'monospace',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
          }}>
            <Terminal size={12} /> SECURE ACCESS TERMINAL
          </div>
        </div>

        <form onSubmit={handleLogin}>
          {['username', 'password', 'otp'].map((field) => {
            const val = field === 'username' ? username : field === 'password' ? password : otp
            const set = field === 'username' ? setUsername : field === 'password' ? setPassword : setOtp
            return (
              <input key={field} className="login-input"
                type={field === 'password' ? 'password' : 'text'}
                placeholder={field === 'otp' ? '6-DIGIT OTP' : field.toUpperCase()}
                value={val} maxLength={field === 'otp' ? 6 : undefined}
                autoFocus={field === 'username'}
                onChange={e => set(e.target.value)}
                style={{
                  width: '100%', padding: '12px 14px', marginBottom: 14,
                  background: 'rgba(6,10,20,0.6)', border: '1px solid rgba(59,130,246,0.2)',
                  borderRadius: 9, color: '#e8eefc', fontSize: 14, outline: 'none',
                  fontFamily: field === 'otp' ? 'monospace' : 'inherit',
                  letterSpacing: field === 'otp' ? 4 : 0, transition: 'all 0.15s',
                }} />
            )
          })}

          {error && (
            <div style={{
              color: '#f87171', fontSize: 12, marginBottom: 14, fontFamily: 'monospace',
              padding: '8px 12px', background: 'rgba(220,38,38,0.1)',
              border: '1px solid rgba(220,38,38,0.3)', borderRadius: 8,
              animation: 'glow 1s ease',
            }}>⚠ {error}</div>
          )}

          <button type="submit" disabled={loading} style={{
            width: '100%', padding: 13, borderRadius: 9, border: 'none',
            background: loading ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #3b82f6)',
            color: '#fff', fontWeight: 600, fontSize: 14, cursor: loading ? 'wait' : 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            letterSpacing: 0.5, transition: 'all 0.2s',
          }}>
            <Lock size={16} /> {loading ? 'AUTHENTICATING…' : 'AUTHENTICATE'}
          </button>
        </form>

        <div style={{
          textAlign: 'center', marginTop: 18, fontSize: 11, color: '#5b6b85',
          fontFamily: 'monospace',
        }}>
          🔒 MFA PROTECTED · TLS ENCRYPTED
        </div>
      </div>
    </div>
  )
}
