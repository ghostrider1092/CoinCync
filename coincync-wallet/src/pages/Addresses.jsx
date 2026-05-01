import { useState, useContext } from "react";
import { useTheme, Card, Btn, Ico, Input, Lbl, ICONS, Divider, EmptyState } from "../components/ui";
import { NotifCtx } from "../appContexts";

const STORAGE_KEY = "cc_address_book";

function loadContacts() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch { return []; }
}
function saveContacts(c) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(c));
}

export default function Addresses() {
  const T = useTheme();
  const { push } = useContext(NotifCtx);
  const [contacts, setContacts] = useState(loadContacts);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState(-1);
  const [name, setName] = useState("");
  const [addr, setAddr] = useState("");
  const [note, setNote] = useState("");

  function addContact() {
    if (!name || !addr) { push("Name and address required","warning"); return; }
    if (!addr.startsWith("tCYNC") && !addr.startsWith("CYNC")) { push("Invalid address","error"); return; }
    const updated = [...contacts, { l:name, a:addr, n:note }];
    setContacts(updated); saveContacts(updated);
    setName(""); setAddr(""); setNote(""); setAdding(false);
    push(`Contact "${name}" saved`,"success");
  }

  function deleteContact(i) {
    const updated = contacts.filter((_,idx) => idx !== i);
    setContacts(updated); saveContacts(updated);
    push("Contact removed","info");
  }

  function copyAddr(address) {
    if (navigator.clipboard) navigator.clipboard.writeText(address);
    else { const ta=document.createElement("textarea"); ta.value=address; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta); }
    push("Address copied","success");
  }

  return (
    <div style={{ animation:"fadeIn .2s ease", maxWidth:"100%" }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:18 }}>
        <div>
          <h1 style={{ fontFamily:T.serif, fontSize:21, fontWeight:400 }}>Address Book</h1>
          <p style={{ fontSize:11, color:T.t3, marginTop:3 }}>{contacts.length} saved contact{contacts.length!==1?"s":""}</p>
        </div>
        <Btn small onClick={()=>setAdding(!adding)}>
          <Ico d={adding?"M18 6L6 18M6 6l12 12":"M12 5v14M5 12h14"} size={13} color="#fff"/>
          {adding?"Cancel":"Add Contact"}
        </Btn>
      </div>

      {/* Add form */}
      {adding && (
        <Card style={{ marginBottom:14, animation:"slideDown .2s ease" }}>
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            <Input label="Name" value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Alice"/>
            <Input label="Address" value={addr} onChange={e=>setAddr(e.target.value)} placeholder="tCYNC3..." mono/>
            <Input label="Note (optional)" value={note} onChange={e=>setNote(e.target.value)} placeholder="e.g. Exchange deposit"/>
            <Btn onClick={addContact} full>Save Contact</Btn>
          </div>
        </Card>
      )}

      {/* Contact list */}
      <Card>
        {contacts.length === 0 ? (
          <EmptyState icon={ICONS.addresses} title="No contacts saved"
            subtitle="Save frequently used addresses for quick access when sending CYNC."
            action={<Btn small onClick={()=>setAdding(true)}>Add Your First Contact</Btn>}/>
        ) : contacts.map((c, i) => (
          <div key={i} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
            padding:"10px 0", borderBottom: i < contacts.length-1 ? `1px solid ${T.b}` : "none" }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, flex:1, minWidth:0 }}>
              <div style={{ width:32, height:32, borderRadius:"50%", background:`${T.ac2}12`,
                display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                <span style={{ fontSize:14 }}>{c.l.charAt(0).toUpperCase()}</span>
              </div>
              <div style={{ minWidth:0 }}>
                <div style={{ fontSize:12, fontWeight:600 }}>{c.l}</div>
                <div style={{ fontSize:9, color:T.t3, fontFamily:T.mono, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{c.a}</div>
                {c.n && <div style={{ fontSize:9, color:T.t3 }}>{c.n}</div>}
              </div>
            </div>
            <div style={{ display:"flex", gap:4, flexShrink:0 }}>
              <Btn small variant="ghost" onClick={()=>copyAddr(c.a)}>
                <Ico d={ICONS.copy} size={10} color={T.ac2}/>
              </Btn>
              <Btn small variant="danger" onClick={()=>deleteContact(i)}>
                <Ico d={ICONS.close} size={10} color={T.red}/>
              </Btn>
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
}
