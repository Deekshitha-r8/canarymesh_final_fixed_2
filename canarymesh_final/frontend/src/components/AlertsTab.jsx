import { Badge, SEV, C } from './shared'

export default function AlertsTab({ alerts = [], approveAlert = () => {}, clearAlerts = () => {} }) {
  return (
    <div>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
        <span style={{fontSize:12,color:C.tm}}>{alerts.length} active alerts</span>
        <button onClick={clearAlerts} style={{fontSize:11,padding:'4px 10px',borderRadius:6,cursor:'pointer',background:'none',border:`1px solid ${C.border}`,color:C.tm}}>Clear all</button>
      </div>
      {alerts.length===0 ? (
        <div style={{textAlign:'center',padding:'50px 0',color:C.tm}}>
          <div style={{fontSize:32,marginBottom:8}}>✓</div>
          <div style={{fontSize:13}}>No active alerts. All devices are operating within policy.</div>
        </div>
      ) : (
        <div style={{display:'flex',flexDirection:'column',gap:8}}>
          {alerts.map(alert => {
            const s = SEV[alert.severity] || SEV.LOW
            return (
              <div key={alert.id} style={{background:C.card,border:`1px solid ${C.border}`,borderLeft:`3px solid ${s.color}`,borderRadius:10,padding:'10px 12px'}}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:5}}>
                  <div style={{display:'flex',alignItems:'center',gap:7}}>
                    <Badge sev={alert.severity}/>
                    <span style={{fontSize:12,fontWeight:600,color:C.tp}}>{alert.node || alert.node_name}</span>
                  </div>
                  <span style={{fontSize:10,color:C.tm,fontFamily:'monospace',flexShrink:0}}>{alert.time || alert.timestamp?.slice(11,19)}</span>
                </div>
                <p style={{fontSize:11,color:C.ts,margin:'0 0 8px',lineHeight:1.5}}>{alert.reason}</p>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                  <span style={{fontSize:10,color:s.color,fontWeight:500}}>● {s.action}</span>
                  {alert.severity === 'MEDIUM' && (
                    <button onClick={() => approveAlert(alert.id)} style={{fontSize:10,padding:'3px 10px',borderRadius:5,cursor:'pointer',background:`${C.amber}20`,border:`1px solid ${C.amber}50`,color:C.amber,fontWeight:600}}>
                      Approve isolation
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
