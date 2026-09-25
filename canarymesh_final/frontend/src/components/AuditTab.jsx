import { useEffect, useState } from 'react'
import { C } from './shared'

const pageHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
const API = (import.meta.env.VITE_API_URL || `http://${pageHost}:8000`).replace(/\/$/, '')
const ACTION_META = {
  isolate:{label:'Isolate',color:C.red}, auto_isolate:{label:'Auto-Isolate',color:'#FF0000'}, sanitize:{label:'Sanitize',color:C.teal},
  block_source:{label:'Block Source',color:C.amber}, purge_queue:{label:'Purge Queue',color:C.amber}, fl_model_reset:{label:'FL Reset',color:C.teal},
  health_check_passed:{label:'Health ✓',color:C.green}, reconnect:{label:'Reconnect',color:C.green}, approve_isolation:{label:'Approved',color:C.amber},
}

export default function AuditTab() {
  const [decisions,setDecisions]=useState([]); const [alerts,setAlerts]=useState([]); const [view,setView]=useState('decisions')
  const refresh=()=>{
    fetch(`${API}/api/audit?limit=100`).then(r=>r.json()).then(d=>setDecisions(d.decisions||[])).catch(()=>{})
    fetch(`${API}/api/alerts?limit=100`).then(r=>r.json()).then(d=>setAlerts(d.alerts||[])).catch(()=>{})
  }
  useEffect(()=>{refresh();const id=setInterval(refresh,5000);return()=>clearInterval(id)},[])
  return <div>
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
      <div style={{display:'flex',gap:8}}>{['decisions','alerts'].map(v=><button key={v} onClick={()=>setView(v)} style={{padding:'8px 14px',borderRadius:8,cursor:'pointer',fontSize:12,background:view===v?`${C.accent}20`:C.card,border:`1px solid ${view===v?C.accent:C.border}`,color:view===v?C.accent:C.ts}}>{v} ({v==='decisions'?decisions.length:alerts.length})</button>)}</div>
      <button onClick={refresh} style={{fontSize:11,padding:'5px 10px',borderRadius:6,cursor:'pointer',background:'none',border:`1px solid ${C.border}`,color:C.tm}}>↻ Refresh</button>
    </div>
    {view==='decisions' ? (decisions.length===0 ? <div style={{textAlign:'center',padding:40,color:C.tm}}>No operator decisions logged yet.</div> : decisions.map((d,i)=>{const am=ACTION_META[d.action]||{label:d.action,color:C.ts};return <div key={d.id||i} style={{background:C.card,border:`1px solid ${C.border}`,borderLeft:`3px solid ${am.color}`,borderRadius:10,padding:'10px 12px',marginBottom:8}}><div style={{display:'flex',justifyContent:'space-between'}}><span style={{fontSize:10,fontWeight:700,color:am.color}}>{am.label}</span><span style={{fontSize:10,color:C.tm}}>{d.timestamp?.slice(11,19)||''}</span></div><div style={{fontSize:11,color:C.ts,marginTop:5}}><b>{d.node_id}</b> · {d.operator} · {d.reason}</div></div>}) ) : (alerts.length===0 ? <div style={{textAlign:'center',padding:40,color:C.tm}}>No alerts in database yet.</div> : alerts.map((a,i)=><div key={a.id||i} style={{background:C.card,border:`1px solid ${C.border}`,borderLeft:`3px solid ${a.severity==='CRITICAL'?C.red:a.severity==='HIGH'?C.red:a.severity==='MEDIUM'?C.amber:C.green}`,borderRadius:10,padding:'10px 12px',marginBottom:8}}><div style={{display:'flex',justifyContent:'space-between'}}><span style={{fontSize:10,fontWeight:700,color:C.tp}}>{a.severity}</span><span style={{fontSize:10,color:C.tm}}>{a.timestamp}</span></div><div style={{fontSize:11,color:C.ts,marginTop:5}}>{a.node_name} · {a.reason}</div></div>))}
  </div>
}
