import { useEffect, useState } from 'react'
import { C } from './shared'

const pageHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
const API = (import.meta.env.VITE_API_URL || `http://${pageHost}:8000`).replace(/\/$/, '')

export default function MQTTTab({ mqttLog, mqttBroker, dataset }) {
  const [rows,setRows]=useState(mqttLog||[])
  useEffect(()=>setRows(mqttLog||[]),[mqttLog])
  useEffect(()=>{let live=true; const refresh=async()=>{try{const res=await fetch(`${API}/api/mqtt/recent?limit=60`,{cache:'no-store'});if(!res.ok)return;const body=await res.json();if(live)setRows(body.messages||[])}catch{}};refresh();const id=window.setInterval(refresh,2500);return()=>{live=false;window.clearInterval(id)}},[])
  return <div>
    <div style={{padding:12,background:C.panel,border:`1px solid ${C.border}`,borderRadius:10,marginBottom:10}}>
      <div style={{display:'flex',justifyContent:'space-between',gap:10}}><div><div style={{fontWeight:700,fontSize:13}}>MQTT publish log</div><div style={{marginTop:4,color:C.ts,fontSize:10}}>Every row is persisted in SQLite. When Mosquitto is available, the same JSON body is also published to the broker.</div></div><div style={{textAlign:'right',fontSize:10,color:mqttBroker?.connected?C.green:C.amber}}><div>{mqttBroker?.connected?'● broker connected':'● recorded only'}</div><div style={{color:C.tm}}>{mqttBroker?.host||'127.0.0.1'}:{mqttBroker?.port||1883}</div></div></div>
      <div style={{marginTop:8,fontSize:9,color:C.tm}}>Dataset source: {dataset?.source || 'Loading'}</div>
    </div>
    {rows.length===0?<div style={{padding:30,textAlign:'center',color:C.tm}}>Waiting for telemetry...</div>:rows.map((row,i)=>{let payload=row.payload;try{payload=JSON.stringify(JSON.parse(row.payload),null,2)}catch{};const attack=String(row.label||'').toLowerCase()!=='normal';return <div key={row.id||`${row.timestamp}-${row.topic}-${i}`} style={{background:C.card,border:`1px solid ${C.border}`,borderLeft:`3px solid ${attack?C.red:C.borderB}`,borderRadius:9,padding:10,marginBottom:7}}><div style={{display:'flex',justifyContent:'space-between',gap:8}}><div style={{fontFamily:'monospace',fontSize:10,color:C.teal}}>{row.topic}</div><div style={{fontSize:9,color:C.tm}}>{row.timestamp}</div></div><div style={{marginTop:6,display:'flex',gap:7,flexWrap:'wrap',fontSize:9}}><span style={{color:C.ts}}>{row.source_name||row.source_id}</span><span style={{color:attack?C.red:C.green}}>{row.label||'normal'}</span><span style={{color:C.tm}}>{row.transport==='mqtt'?'published to broker':'SQLite only'}</span><span style={{color:C.tm}}>{row.dataset}</span></div><pre style={{margin:'7px 0 0',maxHeight:220,overflow:'auto',padding:8,background:'#050a12',borderRadius:7,color:C.tp,fontSize:9,lineHeight:1.5}}>{payload}</pre></div>})}
  </div>
}
