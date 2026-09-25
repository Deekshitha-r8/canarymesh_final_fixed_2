import { useMemo, useState } from 'react'
import { Badge, C, DeviceDetail, Progress, STATUS_META } from './shared'
import AddNodeModal from './AddNodeModal'

function riskColor(device) {
  return ({ LOW: C.green, MEDIUM: C.amber, HIGH: C.red, CRITICAL: '#ff3b30' }[device.severity] || C.ts)
}

export default function NodesTab({ devices, attackTypes, selDevice, setSelDevice, replayAttack, isolateDevice, restoreDevice, sanitizeDevice, reconnectDevice, addDevice }) {
  const [filter, setFilter] = useState('all')
  const [showAddModal, setShowAddModal] = useState(false)
  const realDevices = devices.filter((d) => d.type !== 'Honeypot')
  const visible = realDevices.filter((d) => filter === 'all' || d.severity === filter)
  const selectedOptions = useMemo(() => selDevice ? (attackTypes?.[selDevice.dataset] || []) : [], [attackTypes, selDevice])

  return (
    <div>
      <div style={{ marginBottom: 12, padding: 12, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>Industrial devices</div>
          <div style={{ marginTop: 4, color: C.ts, fontSize: 11, lineHeight: 1.5 }}>These cards are fed from the backend state channel. Real ToN-IoT rows are preferred; when they are unavailable during local testing, the backend uses clearly labelled deterministic offline-demo telemetry.</div>
        </div>
        {addDevice && <button onClick={() => setShowAddModal(true)} style={{ flexShrink: 0, padding: '8px 14px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontWeight: 700, background: C.accent, color: '#fff', border: 0 }}>+ Add device</button>}
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 10, overflowX: 'auto' }}>
        {['all', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((x) => <button key={x} onClick={() => setFilter(x)} style={{ padding: '6px 10px', borderRadius: 7, border: `1px solid ${filter === x ? C.accent : C.border}`, background: filter === x ? `${C.accent}16` : C.card, color: filter === x ? C.accent : C.ts, cursor: 'pointer', fontSize: 10 }}>{x === 'all' ? 'All' : x}</button>)}
      </div>

      {showAddModal && <AddNodeModal onAdd={(name, type, dataset) => addDevice(name, type, dataset)} onClose={() => setShowAddModal(false)} />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(270px,1fr))', gap: 9 }}>
        {visible.map((device) => {
          const color = riskColor(device)
          const status = STATUS_META[device.status] || STATUS_META.normal
          return (
            <button key={device.id} onClick={() => setSelDevice(selDevice?.id === device.id ? null : device)} style={{ textAlign: 'left', background: C.card, color: C.tp, border: `1px solid ${selDevice?.id === device.id ? C.accent : C.border}`, borderRadius: 11, padding: 12, cursor: 'pointer' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: 8 }}>
                <div><div style={{ fontWeight: 700, fontSize: 13 }}>{device.name}</div><div style={{ color: C.tm, fontSize: 9, marginTop: 2 }}>{device.id} · {device.type} · {device.dataset}</div></div>
                <Badge sev={device.severity} />
              </div>
              <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div><div style={{ fontSize: 9, color: C.tm }}>Risk</div><div style={{ color, fontSize: 20, fontWeight: 750 }}>{Number(device.riskScore || 0).toFixed(1)}</div><Progress value={device.riskScore} color={color} /></div>
                <div><div style={{ fontSize: 9, color: C.tm }}>Anomaly</div><div style={{ fontSize: 20, fontWeight: 750 }}>{(Number(device.anomalyScore || 0) * 100).toFixed(1)}%</div><div style={{ fontSize: 9, color: status.color, marginTop: 2 }}>{status.label}</div></div>
              </div>
              <div style={{ marginTop: 9, display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 9 }}>
                <span style={{ color: C.tm }}>Ground truth</span><span style={{ color: device.attackType ? C.red : C.green, fontWeight: 650 }}>{device.attackType || 'normal'}</span>
              </div>
            </button>
          )
        })}
      </div>

      {selDevice && <DeviceDetail
        device={devices.find((d) => d.id === selDevice.id) || selDevice}
        onClose={() => setSelDevice(null)}
        onIsolate={isolateDevice}
        onRestore={restoreDevice}
        onReplayAttack={replayAttack}
        onSanitize={sanitizeDevice}
        onReconnect={reconnectDevice}
        attackOptions={selectedOptions}
      />}
    </div>
  )
}
