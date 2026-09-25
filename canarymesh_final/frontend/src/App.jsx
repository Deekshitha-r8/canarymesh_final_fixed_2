import { useState } from 'react'
import { useWebSocket } from './useWebSocket'
import { C } from './components/shared'
import Dashboard from './components/Dashboard'
import NodesTab from './components/NodesTab'
import AlertsTab from './components/AlertsTab'
import FLTab from './components/FLTab'
import MQTTTab from './components/MQTTTab'
import AuditTab from './components/AuditTab'

export default function App() {
  const ws = useWebSocket()
  const [tab, setTab] = useState('dashboard')
  const [selDevice, setSelDevice] = useState(null)

  const alertCount = ws.alerts.filter((a) => a.severity !== 'LOW').length
  const criticalCount = ws.alerts.filter((a) => a.severity === 'CRITICAL').length

  const tabs = [
    ['dashboard', 'Dashboard'], ['devices', 'Devices'], ['alerts', 'Alerts'],
    ['fl', 'FL Engine'], ['mqtt', 'MQTT Log'], ['audit', 'Audit'],
  ]

  const shared = { ...ws, selDevice, setSelDevice, C }
  const statusText = ws.connected ? 'Live WebSocket' : ws.apiConnected ? 'Backend API live' : 'Backend connecting'
  const statusColor = ws.apiConnected ? C.green : C.amber

  return (
    <div style={{ minHeight: '100vh', background: C.bg, color: C.tp, fontFamily: 'system-ui,-apple-system,sans-serif' }}>
      <header style={{ borderBottom: `1px solid ${C.border}`, background: C.panel, padding: '10px 16px', display: 'flex', gap: 16, justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: `${C.accent}18`, border: `1px solid ${C.accent}55`, display: 'grid', placeItems: 'center', fontWeight: 800 }}>CM</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 750 }}>CanaryMesh</div>
            <div style={{ fontSize: 9, color: C.tm, letterSpacing: '.08em' }}>INDUSTRIAL IoT SECURITY OPERATIONS</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 11 }}>
          {criticalCount > 0 && <div style={{ color: C.red, fontWeight: 700 }}>{criticalCount} critical</div>}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: 99, background: statusColor }} />
            {statusText}
          </div>
        </div>
      </header>

      <nav style={{ display: 'flex', overflowX: 'auto', borderBottom: `1px solid ${C.border}`, background: C.panel }}>
        {tabs.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} style={{ padding: '10px 14px', color: tab === id ? C.accent : C.ts, background: 'none', border: 0, borderBottom: tab === id ? `2px solid ${C.accent}` : '2px solid transparent', fontSize: 12, cursor: 'pointer' }}>
            {label}{id === 'alerts' && alertCount > 0 ? ` (${alertCount})` : ''}
          </button>
        ))}
      </nav>

      <main style={{ padding: 14 }}>
        {ws.apiError && (
          <div style={{ marginBottom: 12, padding: '8px 10px', borderRadius: 8, border: `1px solid ${C.amber}55`, background: `${C.amber}10`, color: C.amber, fontSize: 11 }}>
            {ws.apiError}
          </div>
        )}
        {tab === 'dashboard' && <Dashboard {...shared} />}
        {tab === 'devices' && <NodesTab {...shared} />}
        {tab === 'alerts' && <AlertsTab alerts={ws.alerts} approveAlert={ws.approveAlert} clearAlerts={ws.clearAlerts} />}
        {tab === 'fl' && <FLTab fl={ws.fl} />}
        {tab === 'mqtt' && <MQTTTab mqttLog={ws.mqttLog} mqttBroker={ws.mqttBroker} dataset={ws.dataset} />}
        {tab === 'audit' && <AuditTab />}
      </main>
    </div>
  )
}
