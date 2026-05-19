import { useTheme, Card, Ico, ICONS } from "../components/ui";
export default function Constitution() {
  const T = useTheme();
  return (
    <div style={{animation:"fadeIn .2s ease",maxWidth:620}}>
      <div style={{marginBottom:18}}>
        <h1 style={{fontFamily:T.serif,fontSize:21,fontWeight:400}}>Constitution</h1>
        <p style={{fontFamily:T.serif,fontStyle:"italic",fontSize:12,color:T.ac2,marginTop:3}}>Privacy money that requires no permission.</p>
      </div>

      <div style={{marginBottom:14,padding:"16px 20px",background:`linear-gradient(135deg,rgba(13,122,88,.08),rgba(13,122,88,.02))`,border:`1px solid rgba(13,122,88,.2)`,borderRadius:11}}>
        <div style={{fontFamily:T.serif,fontSize:14,fontStyle:"italic",color:T.t1,lineHeight:1.8,textAlign:"center"}}>
          "The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated."
        </div>
        <div style={{fontFamily:T.mono,fontSize:9,color:T.ac2,textAlign:"center",marginTop:8,letterSpacing:1}}>FOURTH AMENDMENT · U.S. CONSTITUTION · 1791</div>
      </div>

      {[
        ["Article I — Fixed Supply","The total supply of CYNC shall never exceed 100,000,000 coins. Asymptotic emission: reward = max(0.6, (100M - mined) / 2M). No amendment possible.",T.ac2],
        ["Article II — No Dev Tax","No developer tax, no pre-mine, no founder's reward. Zero fee extraction. Fees go to miners (70%) and burn (30%). No protocol treasury.",T.ac2],
        ["Article III — Mandatory Privacy","Every transaction MUST be private. No opt-out. CLSAG ring signatures, stealth addresses, Pedersen commitments, Bulletproofs+ range proofs on every transaction.",T.ac2],
        ["Article V — CPU-Only PoW","RandomX proof of work. ASIC-resistant by design. One CPU, one vote. No GPU advantage. No FPGA advantage.",T.blue],
        ["Article IX — No Surveillance","No blacklists, no address freezing, no censorship hooks, no compliance backdoors. The code physically cannot do these things. The absence of such code IS the enforcement.",T.red],
        ["Bill of Rights IV — 4th Amendment","CoinCync recognizes financial records as 'papers and effects.' Privacy is enforced with cryptography that no warrant can break and no court can override.",T.amber],
      ].map(([title,desc,c])=>(
        <Card key={title} style={{marginBottom:10}}>
          <div style={{fontSize:12,fontWeight:700,color:c,marginBottom:4}}>{title}</div>
          <div style={{fontSize:11,color:T.t2,lineHeight:1.6}}>{desc}</div>
        </Card>
      ))}

      <div style={{textAlign:"center",padding:"16px 0",fontSize:10,color:T.t3,fontFamily:T.mono}}>
        Ratified at Block 0. Permanent thereafter.
      </div>
    </div>
  );
}
