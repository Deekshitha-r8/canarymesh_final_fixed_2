import { useState } from 'react'
import { C, ICONS } from './shared'

const DATASETS = [
  ['modbus', 'PLC'], ['weather', 'Sensor'], ['garage_door', 'Actuator'], ['thermostat', 'Sensor'], ['fridge', 'Sensor'], ['motion_light', 'Sensor'], ['gps_tracker', 'Tracker'],
]

export default function AddNodeModal({ onAdd, onClose }) {
  const [name, setName] = useState('')
  const [dataset, setDataset] = useState('modbus')
  const [error, setError] = useState('')
  const type = DATASETS.find(([d]) => d === dataset)?.[1] || 'Sensor'

  const submit = () => {
    if (name.trim().length < 2) { setError('Use a device name with at least 2 characters'); return }
    onAdd(name.trim(), type, dataset)
    onClose()
  }

  return <div style={{ position: 'fixed', inset: 0, zIndex: 1000, background: '#000b', display: 'grid', placeItems: 'center', padding: 14 }}>
    <div style={{ width: '100%', maxWidth: 420, background: C.panel, border: `1px solid ${C.borderB}`, borderRadius: 12, padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}><div><div style={{ fontWeight: 750 }}>Add benchmark-backed device</div><div style={{ color: C.tm, fontSize: 9, marginTop: 3 }}>The telemetry source must be one of the loaded ToN-IoT subsets.</div></div><button onClick={onClose} style={{ border: 0, background: 'none', color: C.tm, cursor: 'pointer' }}>✕</button></div>
      <div style={{ marginTop: 14 }}><label style={{ display: 'block', color: C.tm, fontSize: 10, marginBottom: 5 }}>Device name</label><input value={name} onChange={(e) => { setName(e.target.value); setError('') }} placeholder="e.g. PLC-07" style={{ width: '100%', boxSizing: 'border-box', padding: 9, borderRadius: 7, background: C.card, color: C.tp, border: `1px solid ${error ? C.red : C.border}` }} />{error && <div style={{ color: C.red, fontSize: 9, marginTop: 4 }}>{error}</div>}</div>
      <div style={{ marginTop: 12 }}><label style={{ display: 'block', color: C.tm, fontSize: 10, marginBottom: 5 }}>Telemetry dataset</label><select value={dataset} onChange={(e) => setDataset(e.target.value)} style={{ width: '100%', padding: 9, borderRadius: 7, background: C.card, color: C.tp, border: `1px solid ${C.border}` }}>{DATASETS.map(([key, kind]) => <option key={key} value={key}>{ICONS[kind] || '◈'} {key} ({kind})</option>)}</select></div>
      <div style={{ marginTop: 12, padding: 9, background: C.card, borderRadius: 8, fontSize: 10, color: C.ts, lineHeight: 1.5 }}>This adds a display device backed by the selected dataset. No random traffic baseline is created.</div>
      <div style={{ display: 'flex', gap: 7, marginTop: 14 }}><button onClick={onClose} style={{ flex: 1, padding: 9, borderRadius: 7, background: 'none', color: C.ts, border: `1px solid ${C.border}` }}>Cancel</button><button onClick={submit} style={{ flex: 1.5, padding: 9, borderRadius: 7, background: C.accent, color: '#fff', border: 0, fontWeight: 700 }}>Add device</button></div>
    </div>
  </div>
}
