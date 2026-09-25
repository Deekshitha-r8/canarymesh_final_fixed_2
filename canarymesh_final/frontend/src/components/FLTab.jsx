import { C } from './shared'

export default function FLTab({ fl }) {
  if (!fl) return <div style={{ padding: 30, textAlign: 'center', color: C.tm }}>Waiting for federated evaluation...</div>
  const rows = Object.values(fl.contributions || {})
  return (
    <div>
      <div style={{ padding: 12, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10, marginBottom: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}><div><div style={{ fontSize: 13, fontWeight: 700 }}>Federated learning</div><div style={{ marginTop: 4, fontSize: 10, color: C.ts }}>{fl.aggregationMethod}</div></div><div style={{ color: C.teal, fontSize: 10 }}>Round {fl.round}</div></div>
        <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <div style={{ background: C.card, borderRadius: 8, padding: 10 }}><div style={{ fontSize: 9, color: C.tm }}>Measured accuracy</div><div style={{ fontSize: 25, fontWeight: 800, color: C.accent }}>{fl.measured ? `${Number(fl.accuracy).toFixed(1)}%` : '—'}</div><div style={{ fontSize: 9, color: C.tm }}>{fl.evaluationSource}</div></div>
          <div style={{ background: C.card, borderRadius: 8, padding: 10 }}><div style={{ fontSize: 9, color: C.tm }}>Raw telemetry shared</div><div style={{ fontSize: 25, fontWeight: 800, color: C.green }}>0</div><div style={{ fontSize: 9, color: C.tm }}>Only compact model parameters are aggregated</div></div>
        </div>
      </div>

      <div style={{ padding: 12, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, marginBottom: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8 }}>Device model updates</div>
        {rows.map((c) => <div key={c.name} style={{ display: 'grid', gridTemplateColumns: '110px 1fr auto', gap: 9, alignItems: 'center', padding: '6px 0', borderBottom: `1px solid ${C.border}` }}><span style={{ fontSize: 10 }}>{c.name}</span><div style={{ height: 4, background: C.border, borderRadius: 99 }}><div style={{ width: `${Math.min(100, Math.abs(Number(c.update_norm || 0)) * 100)}%`, height: '100%', background: c.contributed ? C.accent : C.tm, borderRadius: 99 }} /></div><span style={{ fontSize: 9, color: c.contributed ? C.green : C.tm }}>{c.contributed ? 'contributed' : 'isolated'}</span></div>)}
      </div>

      <div style={{ padding: 12, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 700 }}>What the number means</div>
        <p style={{ color: C.ts, fontSize: 10, lineHeight: 1.6 }}>Accuracy is calculated from held-out labeled ToN-IoT replay rows after the aggregated Isolation Forest offset is applied. The dataset label is used only for evaluation, not as an input feature or risk shortcut.</p>
        <p style={{ color: C.tm, fontSize: 9, lineHeight: 1.6, marginBottom: 0 }}>The current project keeps the supplied architecture's compact offset aggregation. It is not a full Flower server/client implementation, so the UI deliberately does not claim that it is.</p>
      </div>
    </div>
  )
}
