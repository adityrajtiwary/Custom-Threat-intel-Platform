import { useState, useRef, useEffect } from 'react'
import { MessageSquare, X, Send, Bot, User, Loader } from 'lucide-react'
import API from './api'

export default function ChatBot() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState([
    { role: 'bot', text: 'Hi! Ask me about your threat data. Try: "show Bianlian IPs" or "how many critical CVEs".' },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const endRef = useRef(null)

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, loading])

  async function send() {
    const q = input.trim()
    if (!q || loading) return
    setMessages(m => [...m, { role: 'user', text: q }])
    setInput('')
    setLoading(true)
    try {
      const res = await API.post('/chat', { question: q }).then(r => r.data)
      if (res.error) {
        setMessages(m => [...m, { role: 'bot', text: `⚠ ${res.error}`, sql: res.sql }])
      } else {
        setMessages(m => [...m, {
          role: 'bot',
          text: res.count === 0 ? 'No results found.' : `Found ${res.count} result(s):`,
          rows: res.rows, sql: res.sql,
        }])
      }
    } catch (e) {
      setMessages(m => [...m, { role: 'bot', text: '⚠ Something went wrong. Try rephrasing.' }])
    }
    setLoading(false)
  }

  return (
    <>
      {/* floating button */}
      <button onClick={() => setOpen(o => !o)} style={{
        position: 'fixed', bottom: 24, right: 24, zIndex: 200,
        width: 56, height: 56, borderRadius: 28, border: 'none',
        background: 'linear-gradient(135deg, #2563eb, #3b82f6)', color: '#fff',
        cursor: 'pointer', boxShadow: '0 6px 20px rgba(37,99,235,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        transition: 'transform 0.15s',
      }} onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.08)'}
         onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}>
        {open ? <X size={24} /> : <MessageSquare size={24} />}
      </button>

      {/* chat panel */}
      {open && (
        <div style={{
          position: 'fixed', bottom: 92, right: 24, zIndex: 200,
          width: 400, height: 540, background: '#fff',
          border: '1px solid #e4e8ee', borderRadius: 16,
          boxShadow: '0 12px 40px rgba(16,24,40,0.18)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          {/* header */}
          <div style={{
            padding: '16px 18px', borderBottom: '1px solid #e4e8ee',
            display: 'flex', alignItems: 'center', gap: 10,
            background: 'linear-gradient(135deg, #2563eb, #3b82f6)', color: '#fff',
          }}>
            <Bot size={20} />
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>Threat Assistant</div>
              <div style={{ fontSize: 11, opacity: 0.85 }}>Ask your data · read-only</div>
            </div>
          </div>

          {/* messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 16, background: '#f8fafc' }}>
            {messages.map((m, i) => (
              <div key={i} style={{
                display: 'flex', gap: 8, marginBottom: 14,
                flexDirection: m.role === 'user' ? 'row-reverse' : 'row',
              }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 8, flexShrink: 0,
                  background: m.role === 'user' ? '#eff4ff' : '#f0fdf4',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {m.role === 'user' ? <User size={15} color="#2563eb" /> : <Bot size={15} color="#16a34a" />}
                </div>
                <div style={{ maxWidth: '80%' }}>
                  <div style={{
                    padding: '9px 12px', borderRadius: 10, fontSize: 13, lineHeight: 1.5,
                    background: m.role === 'user' ? '#2563eb' : '#fff',
                    color: m.role === 'user' ? '#fff' : '#1a2233',
                    border: m.role === 'user' ? 'none' : '1px solid #e4e8ee',
                  }}>
                    {m.text}
                  </div>

                  {/* result table */}
                  {m.rows && m.rows.length > 0 && (
                    <div style={{
                      marginTop: 6, background: '#fff', border: '1px solid #e4e8ee',
                      borderRadius: 8, overflow: 'auto', maxHeight: 200, fontSize: 12,
                    }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr>{Object.keys(m.rows[0]).map(k => (
                            <th key={k} style={{
                              padding: '6px 8px', textAlign: 'left', background: '#f8fafc',
                              borderBottom: '1px solid #e4e8ee', fontSize: 11, color: '#6b7688',
                              position: 'sticky', top: 0,
                            }}>{k}</th>
                          ))}</tr>
                        </thead>
                        <tbody>
                          {m.rows.slice(0, 20).map((row, ri) => (
                            <tr key={ri}>{Object.values(row).map((v, vi) => (
                              <td key={vi} style={{
                                padding: '6px 8px', borderBottom: '1px solid #f1f3f7',
                                fontFamily: 'monospace', fontSize: 11.5,
                                maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}>{String(v ?? '')}</td>
                            ))}</tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: '#6b7688', fontSize: 13 }}>
                <Loader size={16} className="spin" /> Thinking…
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* input */}
          <div style={{ padding: 12, borderTop: '1px solid #e4e8ee', display: 'flex', gap: 8 }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && send()}
              placeholder="Ask about IOCs, CVEs, groups…"
              style={{
                flex: 1, padding: '10px 12px', border: '1px solid #e4e8ee',
                borderRadius: 9, fontSize: 13, outline: 'none',
              }} />
            <button onClick={send} disabled={loading} style={{
              width: 40, borderRadius: 9, border: 'none', background: '#2563eb',
              color: '#fff', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Send size={16} />
            </button>
          </div>
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg) } } .spin { animation: spin 1s linear infinite }`}</style>
    </>
  )
}
