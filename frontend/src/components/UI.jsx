// components/UI.jsx — 공통 컴포넌트 (엔터프라이즈 급)

export function Badge({ type, children }) {
  const s = {
    crit:   { bg:"rgba(220,38,38,.12)",  color:"#F87171", border:"rgba(220,38,38,.3)" },
    high:   { bg:"rgba(234,88,12,.12)",  color:"#FB923C", border:"rgba(234,88,12,.3)" },
    med:    { bg:"rgba(202,138,4,.12)",   color:"#FBBF24", border:"rgba(202,138,4,.3)" },
    low:    { bg:"rgba(22,163,74,.12)",   color:"#4ADE80", border:"rgba(22,163,74,.3)" },
    info:   { bg:"rgba(37,99,235,.12)",   color:"#60A5FA", border:"rgba(37,99,235,.3)" },
    ok:     { bg:"rgba(22,163,74,.12)",   color:"#4ADE80", border:"rgba(22,163,74,.3)" },
    warn:   { bg:"rgba(234,88,12,.12)",   color:"#FB923C", border:"rgba(234,88,12,.3)" },
    purple: { bg:"rgba(124,58,237,.12)",  color:"#C084FC", border:"rgba(124,58,237,.3)" },
    teal:   { bg:"rgba(13,148,136,.12)",  color:"#2DD4BF", border:"rgba(13,148,136,.3)" },
  }[type] || { bg:"rgba(37,99,235,.12)", color:"#60A5FA", border:"rgba(37,99,235,.3)" };
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", padding:"2px 7px",
      borderRadius:4, fontSize:10, fontWeight:700, whiteSpace:"nowrap",
      background:s.bg, color:s.color, border:`1px solid ${s.border}`, letterSpacing:".02em"
    }}>{children}</span>
  );
}

export function RepBadge({ n }) {
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", gap:3, padding:"2px 6px",
      borderRadius:4, fontSize:9, fontWeight:700,
      background:"rgba(124,58,237,.12)", color:"#C084FC", border:"1px solid rgba(124,58,237,.3)"
    }}>↺ {n}x</span>
  );
}

export function RBar({ pct, color }) {
  return (
    <div style={{ height:4, borderRadius:2, background:"var(--bdr)", overflow:"hidden", width:"100%" }}>
      <div style={{ height:"100%", width:`${Math.min(pct,100)}%`, borderRadius:2, background:color, transition:"width .3s" }} />
    </div>
  );
}

export function Prog({ pct, color }) {
  return (
    <div style={{ height:5, borderRadius:3, background:"var(--bdr)", overflow:"hidden" }}>
      <div style={{ height:"100%", width:`${Math.min(pct,100)}%`, borderRadius:3, background:color, transition:"width .4s" }} />
    </div>
  );
}

export function Card({ children, style }) {
  return (
    <div style={{
      background:"var(--bg-card)", border:"1px solid var(--bdr)",
      borderRadius:10, padding:"16px 18px", boxShadow:"var(--shadow)", ...style
    }}>{children}</div>
  );
}

export function CardHd({ title, right }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14, paddingBottom:10, borderBottom:"1px solid var(--bdr)" }}>
      <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)", letterSpacing:"-.01em" }}>{title}</div>
      <div style={{ display:"flex", gap:6, alignItems:"center" }}>{right}</div>
    </div>
  );
}

export function Th({ children, sortKey, sortState, onSort, style: extraStyle }) {
  const isSorted = sortState?.key === sortKey;
  const asc = sortState?.asc;
  const clickable = !!sortKey;
  return (
    <th onClick={clickable ? () => onSort(sortKey) : undefined}
      style={{
        padding:"9px 10px", textAlign:"left", fontSize:10, fontWeight:700,
        color: isSorted ? "var(--accent-text)" : "var(--txt3)",
        textTransform:"uppercase", letterSpacing:".06em",
        borderBottom:"2px solid var(--bdr)", whiteSpace:"nowrap",
        cursor: clickable ? "pointer" : "default",
        userSelect:"none", background:"var(--bg-card2)",
        transition:"color .15s", ...extraStyle
      }}>
      <span style={{ display:"flex", alignItems:"center", gap:4 }}>
        {children}
        {clickable && <span style={{ fontSize:9, opacity:isSorted?1:.3 }}>{isSorted?(asc?"▲":"▼"):"⇅"}</span>}
      </span>
    </th>
  );
}

export function Td({ children, style }) {
  return (
    <td style={{ padding:"9px 10px", borderBottom:"1px solid var(--bdr)", verticalAlign:"middle", color:"var(--txt)", ...style }}>
      {children}
    </td>
  );
}

export function CheckTd({ checked, onChange }) {
  return (
    <td style={{ padding:"9px 10px", borderBottom:"1px solid var(--bdr)", width:36 }}>
      <div onClick={e=>{e.stopPropagation();onChange(!checked);}}
        style={{ width:15, height:15, borderRadius:3,
          border:`2px solid ${checked?"var(--accent)":"var(--bdr2)"}`,
          background:checked?"var(--accent)":"transparent",
          cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", transition:"all .15s" }}>
        {checked && <span style={{ color:"#fff", fontSize:9, lineHeight:1, fontWeight:700 }}>✓</span>}
      </div>
    </td>
  );
}

export function Tbl({ heads, children }) {
  return (
    <div style={{ overflowX:"auto" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
        <thead><tr>{heads.map((h,i)=><Th key={i}>{h}</Th>)}</tr></thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Pagination({ total, page, pageSize, onPage, onPageSize }) {
  const totalPages = Math.ceil(total / pageSize);
  if (total === 0) return null;
  const start = (page-1)*pageSize+1;
  const end   = Math.min(page*pageSize, total);
  const range = [];
  for (let i=Math.max(1,page-2); i<=Math.min(totalPages,page+2); i++) range.push(i);
  const btn = (label, p, disabled, active) => (
    <button key={label} onClick={()=>!disabled&&onPage(p)} disabled={disabled}
      style={{ padding:"5px 9px", borderRadius:5, border:`1px solid ${active?"var(--accent)":"var(--bdr)"}`,
        background:active?"var(--accent)":"transparent",
        color:active?"#fff":disabled?"var(--bdr2)":"var(--txt2)",
        fontSize:11, cursor:disabled?"default":"pointer", fontWeight:active?700:400,
        minWidth:30, textAlign:"center", transition:"all .15s", opacity:disabled?.4:1 }}>
      {label}
    </button>
  );
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"10px 0", flexWrap:"wrap", gap:8, borderTop:"1px solid var(--bdr)" }}>
      <span style={{ fontSize:11, color:"var(--txt3)" }}>
        전체 <strong style={{ color:"var(--txt)" }}>{total.toLocaleString()}</strong>건 중{" "}
        <strong style={{ color:"var(--txt)" }}>{start}–{end}</strong>
      </span>
      <div style={{ display:"flex", alignItems:"center", gap:4 }}>
        {btn("«",1,page===1,false)}
        {btn("‹",page-1,page===1,false)}
        {range[0]>1 && <span style={{ color:"var(--txt3)", padding:"0 2px", fontSize:11 }}>…</span>}
        {range.map(p=>btn(p,p,false,p===page))}
        {range[range.length-1]<totalPages && <span style={{ color:"var(--txt3)", padding:"0 2px", fontSize:11 }}>…</span>}
        {btn("›",page+1,page===totalPages,false)}
        {btn("»",totalPages,page===totalPages,false)}
        <select value={pageSize} onChange={e=>onPageSize(Number(e.target.value))}
          style={{ padding:"4px 8px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt2)", fontSize:11, cursor:"pointer", marginLeft:6 }}>
          {[10,20,50,100].map(n=><option key={n} value={n}>{n}건</option>)}
        </select>
      </div>
    </div>
  );
}

export function DeleteConfirm({ count, onConfirm, onCancel }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 12px",
      background:"rgba(220,38,38,.08)", border:"1px solid rgba(220,38,38,.3)",
      borderRadius:7, marginBottom:8, flexWrap:"wrap" }}>
      <span style={{ fontSize:12, color:"#F87171", flex:1 }}>
        선택한 <strong>{count}</strong>건을 삭제합니까? 이 작업은 되돌릴 수 없습니다.
      </span>
      <button onClick={onConfirm} style={{ padding:"5px 14px", borderRadius:5, border:"none", background:"#DC2626", color:"#fff", fontSize:12, fontWeight:700, cursor:"pointer" }}>삭제</button>
      <button onClick={onCancel}  style={{ padding:"5px 12px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>취소</button>
    </div>
  );
}

export function SearchBar({ value, onChange, placeholder="검색...", children }) {
  return (
    <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:10, flexWrap:"wrap" }}>
      <div style={{ position:"relative", flex:1, minWidth:180 }}>
        <span style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)", color:"var(--txt3)", fontSize:13, pointerEvents:"none" }}>⌕</span>
        <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
          style={{ width:"100%", padding:"7px 10px 7px 30px", borderRadius:6, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, outline:"none" }}/>
      </div>
      {children}
    </div>
  );
}

export function FilterSelect({ value, onChange, options, placeholder="전체" }) {
  return (
    <select value={value} onChange={e=>onChange(e.target.value)}
      style={{ padding:"7px 10px", borderRadius:6, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, cursor:"pointer", outline:"none" }}>
      <option value="">{placeholder}</option>
      {options.map(o=>(
        <option key={typeof o==="string"?o:o.value} value={typeof o==="string"?o:o.value}>
          {typeof o==="string"?o:o.label}
        </option>
      ))}
    </select>
  );
}

export function TableActions({ selected, total, onSelectAll, onDeselectAll, onDelete, children }) {
  const allSel = selected>0 && selected===total;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
      <div onClick={allSel?onDeselectAll:onSelectAll}
        style={{ width:15, height:15, borderRadius:3,
          border:`2px solid ${selected>0?"var(--accent)":"var(--bdr2)"}`,
          background:allSel?"var(--accent)":selected>0?"rgba(37,99,235,.25)":"transparent",
          cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, transition:"all .15s" }}>
        {allSel && <span style={{ color:"#fff", fontSize:9, fontWeight:700 }}>✓</span>}
        {!allSel && selected>0 && <span style={{ color:"var(--accent-text)", fontSize:8, fontWeight:700 }}>−</span>}
      </div>
      {selected>0 ? (
        <>
          <span style={{ fontSize:12, color:"var(--accent-text)", fontWeight:500 }}>{selected}건 선택됨</span>
          <button onClick={onDelete}
            style={{ padding:"4px 12px", borderRadius:5, border:"1px solid rgba(220,38,38,.4)", background:"rgba(220,38,38,.1)", color:"#F87171", fontSize:11, fontWeight:600, cursor:"pointer" }}>
            🗑 삭제
          </button>
          <button onClick={onDeselectAll}
            style={{ padding:"4px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:11, cursor:"pointer" }}>
            선택 해제
          </button>
        </>
      ) : (
        <span style={{ fontSize:11, color:"var(--txt3)" }}>행을 클릭하여 선택</span>
      )}
      <div style={{ marginLeft:"auto", display:"flex", gap:6 }}>{children}</div>
    </div>
  );
}

export function Chip({ type, label }) {
  const s = {
    online: { bg:"rgba(22,163,74,.1)",  bdr:"rgba(22,163,74,.3)",  color:"#4ADE80", dot:"#22C55E" },
    scan:   { bg:"rgba(37,99,235,.1)",  bdr:"rgba(37,99,235,.3)",  color:"#60A5FA", dot:"#2563EB" },
    off:    { bg:"rgba(220,38,38,.1)",  bdr:"rgba(220,38,38,.3)",  color:"#F87171", dot:"#EF4444" },
    warn:   { bg:"rgba(234,88,12,.1)",  bdr:"rgba(234,88,12,.3)",  color:"#FB923C", dot:"#F97316" },
  }[type] || { bg:"rgba(100,116,139,.1)", bdr:"rgba(100,116,139,.3)", color:"#94A3B8", dot:"#64748B" };
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:5, padding:"3px 9px", borderRadius:20, fontSize:10, fontWeight:600, background:s.bg, border:`1px solid ${s.bdr}`, color:s.color }}>
      <span style={{ width:5, height:5, borderRadius:"50%", background:s.dot, display:"inline-block" }} />
      {label}
    </span>
  );
}

export function EmptyState({ icon, title, desc, action }) {
  return (
    <div style={{ textAlign:"center", padding:"60px 20px" }}>
      <div style={{ fontSize:40, marginBottom:16, opacity:.5 }}>{icon}</div>
      <div style={{ fontSize:15, fontWeight:600, color:"var(--txt)", marginBottom:8 }}>{title}</div>
      <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:20, lineHeight:1.6 }}>{desc}</div>
      {action}
    </div>
  );
}

export function Spinner({ size=12 }) {
  return (
    <div style={{ width:size, height:size, borderRadius:"50%", border:`2px solid var(--accent)`, borderTopColor:"transparent", animation:"spin 0.8s linear infinite", display:"inline-block", flexShrink:0 }} />
  );
}

export function SectionHd({ title, right }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", margin:"20px 0 10px" }}>
      <h2 style={{ fontSize:13, fontWeight:600, color:"var(--txt2)" }}>{title}</h2>
      {right}
    </div>
  );
}

export function InfoTip({ text }) {
  return (
    <span title={text} style={{ display:"inline-flex", alignItems:"center", justifyContent:"center", width:14, height:14, borderRadius:"50%", fontSize:9, fontWeight:700, background:"var(--bg-card2)", color:"var(--txt3)", border:"1px solid var(--bdr2)", cursor:"help", marginLeft:4, flexShrink:0 }}>?</span>
  );
}

export function Btn({ children, onClick, variant="default", size="md", disabled, style:extraStyle }) {
  const p = { sm:"4px 10px", md:"7px 16px", lg:"10px 22px" }[size]||"7px 16px";
  const fs = { sm:11, md:12, lg:13 }[size]||12;
  const v = {
    default: { bg:"var(--bg-card2)", color:"var(--txt2)",  bdr:"var(--bdr2)" },
    primary: { bg:"var(--accent)",   color:"#fff",         bdr:"var(--accent)" },
    danger:  { bg:"rgba(220,38,38,.1)", color:"#F87171",   bdr:"rgba(220,38,38,.4)" },
    success: { bg:"rgba(22,163,74,.1)", color:"#4ADE80",   bdr:"rgba(22,163,74,.4)" },
    ghost:   { bg:"transparent",     color:"var(--txt3)",  bdr:"var(--bdr)" },
  }[variant]||{};
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ padding:p, borderRadius:6, border:`1px solid ${v.bdr}`, background:v.bg, color:v.color, fontSize:fs, fontWeight:600, cursor:disabled?"not-allowed":"pointer", opacity:disabled?.5:1, display:"inline-flex", alignItems:"center", gap:5, whiteSpace:"nowrap", transition:"all .15s", ...extraStyle }}>
      {children}
    </button>
  );
}
