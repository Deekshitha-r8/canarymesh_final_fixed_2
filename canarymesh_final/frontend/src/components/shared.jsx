export const C = {
  bg: '#08101d',
  panel: '#0d1727',
  card: '#111d31',
  border: '#20324f',
  borderB: '#2e4670',
  accent: '#3b82f6',
  teal: '#14b8a6',
  green: '#22c55e',
  amber: '#f59e0b',
  red: '#ef4444',
  purple: '#8b5cf6',
  tp: '#e5eefb',
  ts: '#9db0c9',
  tm: '#5d7393',
}

export const SEV = {
  LOW: { label: 'Low', color: C.green, bg: '#082417', action: 'Observe' },
  MEDIUM: { label: 'Medium', color: C.amber, bg: '#2b1d08', action: 'Pending approval' },
  HIGH: { label: 'High', color: C.red, bg: '#2c0d0d', action: 'Auto-isolate' },
  CRITICAL: { label: 'Critical', color: '#ff3b30', bg: '#300808', action: 'Quarantine' },
}

export const ICONS = { PLC: '⚙', Sensor: '◈', Actuator: '◉', SCADA: '▣', HMI: '⬡', Tracker: '⌁', Honeypot: '⬟' }

export const STATUS_META = {
  normal: { label: 'Normal', color: C.green },
  suspicious: { label: 'Suspicious', color: C.amber },
  compromised: { label: 'Compromised', color: C.red },
  isolated: { label: 'Isolated', color: C.red },
  sanitizing: { label: 'Sanitizing', color: C.amber },
  health_check: { label: 'Health check', color: C.teal },
  ready_reconnect: { label: 'Ready to reconnect', color: C.green },
  honeypot: { label: 'Honeypot', color: C.purple },
}

export function Badge({ sev }) {
  const s = SEV[sev] || SEV.LOW
  return <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, color: s.color, background: s.bg, border: `1px solid ${s.color}44` }}>{s.label}</span>
}

export function StatusBadge({ status }) {
  const s = STATUS_META[status] || STATUS_META.normal
  return <span style={{ fontSize: 10, color: s.color, fontWeight: 600 }}>{s.label}</span>
}

export function StatCard({ label, value, unit, color = C.tp, sub }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 12 }}>
      <div style={{ fontSize: 10, color: C.tm, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 23, fontWeight: 750, color }}>{value}{unit && <span style={{ fontSize: 11, color: C.tm, marginLeft: 3, fontWeight: 400 }}>{unit}</span>}</div>
      {sub && <div style={{ fontSize: 10, color: C.tm, marginTop: 3 }}>{sub}</div>}
    </div>
  )
}

export function Progress({ value, color = C.accent }) {
  const width = Math.max(0, Math.min(100, Number(value) || 0))
  return <div style={{ height: 5, background: C.border, borderRadius: 99, overflow: 'hidden' }}><div style={{ width: `${width}%`, height: '100%', background: color, transition: 'width .5s ease' }} /></div>
}

export function SanitProgress({ device }) {
  if (!device?.sanitStep) return null
  const steps = ['Source blocked', 'Queue purged', 'FL reset', 'Health check']
  return (
    <div style={{ marginTop: 12, padding: 10, background: C.card, borderRadius: 8, border: `1px solid ${C.border}` }}>
      <div style={{ fontSize: 10, color: C.amber, fontWeight: 700, marginBottom: 7 }}>Sanitization step {device.sanitStep}/{device.sanitTotal || 4}</div>
      <div style={{ display: 'flex', gap: 4 }}>
        {steps.map((label, i) => <div key={label} style={{ flex: 1 }}><div style={{ height: 3, background: i < device.sanitStep ? C.green : C.border, borderRadius: 3 }} /><div style={{ fontSize: 8, color: C.tm, marginTop: 3, textAlign: 'center' }}>{label}</div></div>)}
      </div>
      {device.flRoundRestored && <div style={{ marginTop: 6, fontSize: 9, color: C.teal }}>Restored global FL round #{device.flRoundRestored}</div>}
    </div>
  )
}

function featureEntries(device) {
  return Object.entries(device?.lastEvidence?.features || {})
}

export function DeviceDetail({ device, onClose, onIsolate, onRestore, onReplayAttack, onSanitize, onReconnect, attackOptions = [] }) {
  if (!device) return null
  const isHoneypot = device.type === 'Honeypot'
  const sev = SEV[device.severity] || SEV.LOW
  const evidence = featureEntries(device)
  return (
    <section style={{ marginTop: 12, background: C.panel, border: `1px solid ${C.borderB}`, borderRadius: 12, padding: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'start' }}>
        <div style={{ display: 'flex', gap: 9, alignItems: 'center' }}>
          <div style={{ fontSize: 20 }}>{ICONS[device.type] || '◈'}</div>
          <div><div style={{ fontWeight: 700 }}>{device.name}</div><div style={{ fontSize: 10, color: C.tm }}>{device.id} · {device.type}</div></div>
        </div>
        <button onClick={onClose} style={{ border: 0, background: 'none', color: C.tm, cursor: 'pointer' }}>✕</button>
      </div>

      {isHoneypot ? (
        <div style={{ marginTop: 12, padding: 10, borderRadius: 8, background: C.card, color: C.ts, fontSize: 11, lineHeight: 1.6 }}>
          Decoy industrial device. Any unauthorized interaction is treated as a detection signal. The attack demo uses a controlled probe rather than an actual external intrusion.
        </div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginTop: 12 }}>
            {[
              ['Risk score', `${Number(device.riskScore || 0).toFixed(1)}/100`, sev.color],
              ['Anomaly', `${(Number(device.anomalyScore || 0) * 100).toFixed(1)}%`, sev.color],
              ['Persistence', `${(Number(device.persistenceScore || 0) * 100).toFixed(1)}%`, C.teal],
            ].map(([k, v, color]) => <div key={k} style={{ background: C.card, borderRadius: 8, padding: 9 }}><div style={{ fontSize: 9, color: C.tm }}>{k}</div><div style={{ marginTop: 3, fontSize: 18, fontWeight: 750, color }}>{v}</div></div>)}
          </div>

          <div style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between', fontSize: 10 }}>
            <span style={{ color: C.tm }}>Severity</span><Badge sev={device.severity} />
          </div>

          <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div style={{ background: C.card, borderRadius: 8, padding: 9 }}><div style={{ fontSize: 9, color: C.tm }}>Dataset</div><div style={{ marginTop: 3, fontSize: 11, fontWeight: 650 }}>{device.dataset}</div></div>
            <div style={{ background: C.card, borderRadius: 8, padding: 9 }}><div style={{ fontSize: 9, color: C.tm }}>Ground truth</div><div style={{ marginTop: 3, fontSize: 11, fontWeight: 650, color: device.attackType ? C.red : C.green }}>{device.attackType || 'normal'}</div></div>
          </div>

          {device.mqttSample && <div style={{ marginTop: 12 }}><div style={{ fontSize: 10, color: C.tm, marginBottom: 5 }}>Latest MQTT payload</div><pre style={{ margin: 0, maxHeight: 160, overflow: 'auto', padding: 10, background: '#050a12', borderRadius: 8, color: device.mqttSample.type === 'ATTACK' ? '#ff918b' : '#9ee6b7', fontSize: 10, lineHeight: 1.5 }}>{JSON.stringify(device.mqttSample, null, 2)}</pre></div>}

          {evidence.length > 0 && <div style={{ marginTop: 12 }}><div style={{ fontSize: 10, color: C.tm, marginBottom: 5 }}>Measured telemetry features</div><div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>{evidence.map(([k, v]) => <div key={k} style={{ background: C.card, borderRadius: 7, padding: 8 }}><div style={{ fontSize: 8, color: C.tm }}>{k}</div><div style={{ fontSize: 11, color: C.tp, marginTop: 2 }}>{typeof v === 'number' ? v.toFixed(3) : String(v)}</div></div>)}</div></div>}

          <div style={{ marginTop: 12, padding: 10, background: C.card, borderRadius: 8, fontSize: 11, color: C.ts, lineHeight: 1.6 }}><strong style={{ color: C.tp }}>Why this risk?</strong><br />{device.threatReason}</div>
          <div style={{ marginTop: 12, padding: 10, background: `${C.accent}0d`, borderRadius: 8, border: `1px solid ${C.accent}33`, fontSize: 10, color: C.ts }}>Risk is an operational policy score derived from measured anomaly, persistence, and evidence. It is not a probability of compromise.</div>
          <SanitProgress device={device} />

          <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
            {attackOptions.length > 0 && !device.isIsolated && (
              <select id={`attack-${device.id}`} style={{ gridColumn: '1 / -1', width: '100%', padding: 8, borderRadius: 7, background: C.card, color: C.tp, border: `1px solid ${C.border}` }}>
                {attackOptions.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            )}
            {!device.isIsolated && device.status !== 'sanitizing' && device.status !== 'health_check' && device.status !== 'ready_reconnect' && (
              <button onClick={() => onReplayAttack(device.id, document.getElementById(`attack-${device.id}`)?.value || attackOptions[0])} style={{ padding: 9, borderRadius: 7, cursor: 'pointer', background: `${C.red}15`, color: C.red, border: `1px solid ${C.red}55`, fontWeight: 650 }}>Replay labeled attack</button>
            )}
            {!device.isIsolated && ['MEDIUM', 'HIGH', 'CRITICAL'].includes(device.severity) && (
              <button onClick={() => onIsolate(device.id)} style={{ padding: 9, borderRadius: 7, cursor: 'pointer', background: `${C.red}12`, color: C.red, border: `1px solid ${C.red}55`, fontWeight: 650 }}>Isolate device</button>
            )}
            {(device.isIsolated || device.status === 'isolated') && <><button onClick={() => onSanitize(device.id)} style={{ padding: 9, borderRadius: 7, cursor: 'pointer', background: `${C.teal}12`, color: C.teal, border: `1px solid ${C.teal}55`, fontWeight: 650 }}>Sanitize & health check</button><button onClick={() => onRestore(device.id)} style={{ padding: 9, borderRadius: 7, cursor: 'pointer', background: 'none', color: C.ts, border: `1px solid ${C.border}` }}>Restore now</button></>}
            {device.status === 'ready_reconnect' && <button onClick={() => onReconnect(device.id)} style={{ gridColumn: '1 / -1', padding: 9, borderRadius: 7, cursor: 'pointer', background: `${C.green}15`, color: C.green, border: `1px solid ${C.green}55`, fontWeight: 750 }}>Approve reconnection</button>}
          </div>
        </>
      )}
    </section>
  )
}
