import { useCallback, useEffect, useRef, useState } from 'react'

const pageHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
const API_URL = (import.meta.env.VITE_API_URL || `http://${pageHost}:8000`).replace(/\/$/, '')
const WS_URL = import.meta.env.VITE_WS_URL || `ws://${pageHost}:8000/ws`

function mergeMessages(prev, incoming) {
  const rows = [...incoming, ...prev]
  const seen = new Set()
  const out = []
  for (const row of rows) {
    const key = row.id ?? `${row.timestamp || row.time}|${row.topic}|${row.payload}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(row)
    if (out.length >= 100) break
  }
  return out
}

export function useWebSocket() {
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const stoppedRef = useRef(false)

  const [devices, setDevices] = useState([])
  const [alerts, setAlerts] = useState([])
  const [fl, setFl] = useState(null)
  const [connected, setConnected] = useState(false)
  const [apiConnected, setApiConnected] = useState(false)
  const [mqttLog, setMqttLog] = useState([])
  const [sanitLog, setSanitLog] = useState([])
  const [dataset, setDataset] = useState(null)
  const [mqttBroker, setMqttBroker] = useState(null)
  const [attackTypes, setAttackTypes] = useState({})
  const [apiError, setApiError] = useState('')

  const applyState = useCallback((state) => {
    if (Array.isArray(state?.devices)) setDevices(state.devices)
    else if (Array.isArray(state?.nodes)) setDevices(state.nodes)
    if (Array.isArray(state?.alerts)) setAlerts(state.alerts)
    if (state?.fl) setFl(state.fl)
    if (Array.isArray(state?.mqtt)) setMqttLog((prev) => mergeMessages(prev, state.mqtt))
    if (state?.dataset) setDataset(state.dataset)
    if (state?.mqttBroker) setMqttBroker(state.mqttBroker)
    if (state?.startupError && !state?.devices?.length) setApiError(state.startupError)
  }, [])

  const refreshFromApi = useCallback(async () => {
    try {
      const [healthRes, stateRes, mqttRes, attacksRes] = await Promise.all([
        fetch(`${API_URL}/api/health`, { cache: 'no-store' }),
        fetch(`${API_URL}/api/state`, { cache: 'no-store' }),
        fetch(`${API_URL}/api/mqtt/recent?limit=60`, { cache: 'no-store' }),
        fetch(`${API_URL}/api/dataset/attack-types`, { cache: 'no-store' }),
      ])

      if (!healthRes.ok || !stateRes.ok) throw new Error(`Backend HTTP error (${stateRes.status})`)

      const health = await healthRes.json()
      const state = await stateRes.json()
      applyState(state)
      setApiConnected(Boolean(health.backend))

      if (mqttRes.ok) {
        const mqtt = await mqttRes.json()
        setMqttLog((prev) => mergeMessages(prev, mqtt.messages || []))
      }
      if (attacksRes.ok) setAttackTypes(await attacksRes.json())

      setApiError(state.startupError || health.startupError || '')
    } catch (err) {
      setApiConnected(false)
      setApiError(err?.message || 'Cannot reach CanaryMesh backend')
    }
  }, [applyState])

  useEffect(() => {
    refreshFromApi()
    const timer = window.setInterval(refreshFromApi, 2500)
    return () => window.clearInterval(timer)
  }, [refreshFromApi])

  useEffect(() => {
    stoppedRef.current = false

    const connect = () => {
      if (stoppedRef.current) return
      try {
        const socket = new WebSocket(WS_URL)
        wsRef.current = socket

        socket.onopen = () => {
          setConnected(true)
        }
        socket.onclose = () => {
          setConnected(false)
          if (!stoppedRef.current) reconnectTimer.current = window.setTimeout(connect, 2000)
        }
        socket.onerror = () => setConnected(false)
        socket.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data)
            if (msg.type === 'init' || msg.type === 'state_update') {
              applyState(msg)
              return
            }
            if (msg.type === 'dataset_attack_replay') {
              setSanitLog((prev) => [{
                time: new Date().toLocaleTimeString(),
                node: msg.device_id,
                message: `Replayed ${msg.attack_type || 'labeled attack'} from ${msg.source_timestamp || 'benchmark row'}`,
                type: 'attack_replay',
              }, ...prev].slice(0, 50))
              return
            }
            if (msg.type === 'device_added' && msg.device) {
              setDevices((prev) => [...prev.filter((d) => d.id !== msg.device.id), msg.device])
              return
            }
            if (msg.type === 'sanitization_started') {
              setDevices((prev) => prev.map((d) => d.id === msg.node_id ? { ...d, status: 'sanitizing' } : d))
              setSanitLog((prev) => [{
                time: new Date().toLocaleTimeString(), node: msg.node_name,
                message: `Sanitization started for ${msg.node_name}`, type: 'start',
              }, ...prev].slice(0, 50))
              return
            }
            if (msg.type === 'sanitization_progress') {
              const status = msg.phase === 'health_check' ? 'health_check' : 'sanitizing'
              setDevices((prev) => prev.map((d) => d.id === msg.node_id ? {
                ...d, status, sanitStep: msg.step, sanitTotal: msg.total_steps, flRoundRestored: msg.fl_round,
              } : d))
              setSanitLog((prev) => [{
                time: new Date().toLocaleTimeString(), node: msg.node_id, message: msg.message, type: msg.phase,
              }, ...prev].slice(0, 50))
              return
            }
            if (msg.type === 'sanitization_complete') {
              setDevices((prev) => prev.map((d) => d.id === msg.node_id ? {
                ...d, status: msg.passed ? 'ready_reconnect' : 'isolated', sanitStep: msg.passed ? 4 : null,
              } : d))
              return
            }
            if (msg.type === 'node_reconnected') {
              setDevices((prev) => prev.map((d) => d.id === msg.node_id ? {
                ...d, status: 'normal', isIsolated: false, sanitStep: null,
              } : d))
              return
            }
            if (msg.type === 'alerts_cleared') setAlerts([])
            if (msg.type === 'error') setApiError(msg.message || 'Backend error')
          } catch {
            setApiError('Invalid WebSocket message')
          }
        }
      } catch (err) {
        setConnected(false)
        setApiError(err?.message || 'WebSocket unavailable')
        if (!stoppedRef.current) reconnectTimer.current = window.setTimeout(connect, 2000)
      }
    }

    connect()
    return () => {
      stoppedRef.current = true
      if (reconnectTimer.current) window.clearTimeout(reconnectTimer.current)
      try { wsRef.current?.close() } catch {}
    }
  }, [applyState])

  const post = useCallback(async (path, options = {}) => {
    try {
      const response = await fetch(`${API_URL}${path}`, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      })
      const body = await response.json().catch(() => ({}))
      if (!response.ok || body.success === false) throw new Error(body.error || `HTTP ${response.status}`)
      setApiError('')
      return body
    } catch (err) {
      setApiError(err?.message || 'Request failed')
      return null
    }
  }, [])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return Promise.resolve(true)
    }

    const id = data.node_id || data.device_id
    const action = data.action
    const restFallbacks = {
      isolate: id ? `/api/devices/${id}/isolate` : null,
      sanitize: id ? `/api/nodes/${id}/sanitize` : null,
      reconnect: id ? `/api/nodes/${id}/reconnect` : null,
      restore: id ? `/api/nodes/${id}/restore` : null,
      approve_isolation: id ? `/api/alerts/${id}/approve` : null,
      clear_alerts: '/api/alerts/clear',
    }
    const path = restFallbacks[action]
    if (!path) {
      setApiError('Live channel is not connected')
      return Promise.resolve(false)
    }
    return post(path, { method: 'POST' }).then((result) => Boolean(result))
  }, [post])

  const replayAttack = useCallback((deviceId, attackType) => post(`/api/devices/${deviceId}/replay-attack`, {
    method: 'POST',
    body: JSON.stringify({ device_id: deviceId, attack_type: attackType || null }),
  }), [post])

  const addDevice = useCallback((name, nodeType, dataset) => post('/api/devices', {
    method: 'POST',
    body: JSON.stringify({ name, node_type: nodeType, dataset }),
  }).then((result) => Boolean(result?.success)), [post])

  const approveAlert = useCallback((alertId) => {
  const alert = alerts.find((item) => item.id === alertId)

  if (!alert) {
    return Promise.resolve(false)
  }

  if (alert.severity !== 'MEDIUM') {
    return Promise.resolve(false)
  }

  return post(`/api/alerts/${alertId}/approve`, {
    method: 'POST',
  }).then((result) => Boolean(result?.success))
}, [alerts, post])

  return {
    devices,
    nodes: devices,
    alerts,
    fl,
    connected,
    apiConnected,
    mqttLog,
    sanitLog,
    dataset,
    mqttBroker,
    attackTypes,
    apiError,
    isolateDevice: (id) => send({ action: 'isolate', node_id: id }),
    isolateNode: (id) => send({ action: 'isolate', node_id: id }),
    sanitizeDevice: (id) => send({ action: 'sanitize', node_id: id }),
    sanitizeNode: (id) => send({ action: 'sanitize', node_id: id }),
    reconnectDevice: (id) => send({ action: 'reconnect', node_id: id }),
    reconnectNode: (id) => send({ action: 'reconnect', node_id: id }),
    restoreDevice: (id) => send({ action: 'restore', node_id: id }),
    restoreNode: (id) => send({ action: 'restore', node_id: id }),
    replayAttack,
    addDevice,
    triggerHoneypot: () => post('/api/simulate/honeypot_probe', { method: 'POST' }),
    approveAlert,
    clearAlerts: () => send({ action: 'clear_alerts' }),
  }
}
