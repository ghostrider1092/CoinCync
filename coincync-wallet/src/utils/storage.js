export const defaults = {
  daemonAddr:"127.0.0.1:28081",network:"testnet",torEnabled:false,
  ringSize:11,dandelion:true,autoChurn:false,scanOnStart:true,
  autoLockMinutes:15,
};
export const loadSettings  = ()=>{ try{const s=localStorage.getItem("cc_settings"); return s?{...defaults,...JSON.parse(s)}:{...defaults};}catch{return{...defaults};} };
export const saveSettings  = s=>{ try{localStorage.setItem("cc_settings",JSON.stringify(s));}catch{} };
export const loadTheme     = ()=>{
  const saved = localStorage.getItem("cc_theme");
  if (!saved) { localStorage.setItem("cc_theme","dark"); return "dark"; }
  return saved;
};
export const saveTheme     = t=>localStorage.setItem("cc_theme",t);
export const isWalletCreated  = ()=>!!localStorage.getItem("cc_wallet_created");
export const markWalletCreated= ()=>localStorage.setItem("cc_wallet_created","1");
export const isSeedBackedUp   = ()=>!!localStorage.getItem("cc_seed_backed");
export const markSeedBackedUp = ()=>localStorage.setItem("cc_seed_backed","1");
export const clearCoincyncLocalState = ()=>{
  try {
    const keys = Object.keys(localStorage);
    for (const k of keys) {
      if (k.startsWith("cc_")) localStorage.removeItem(k);
    }
  } catch {}
};
