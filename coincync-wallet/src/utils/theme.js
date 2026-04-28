// CoinCync wallet themes — matches explorer 9-theme system

const _fonts = {
  serif:"'Fraunces',Georgia,serif",
  mono:"'JetBrains Mono','Fira Code',monospace",
};

export const THEMES = {
  dark: {
    bg:"#0a0a09",panel:"#111110",card:"#181816",b:"#25241f",b2:"#34332c",
    ac:"#9e7a3e",ac2:"#d4a059",acb:"rgba(212,160,89,0.06)",
    teal:"#d4a059",teal2:"#9e7a3e",tbg:"rgba(212,160,89,0.06)",
    blue:"#6b8cce",amber:"#e8b86d",red:"#c45c4f",green:"#7eb87c",
    t1:"#f5f0e8",t2:"#b8b4ac",t3:"#5d5953",
    inputBg:"#111110",shadow:"rgba(0,0,0,.4)",..._fonts,
  },
  paper: {
    bg:"#F5F3EE",panel:"#FEFDFB",card:"#FEFDFB",b:"#D8D4CA",b2:"#C8C2B8",
    ac:"#9e7a3e",ac2:"#d4a059",acb:"rgba(212,160,89,0.08)",
    teal:"#9e7a3e",teal2:"#7a5e2e",tbg:"rgba(158,122,62,0.06)",
    blue:"#4a6a9e",amber:"#9e7a3e",red:"#b03030",green:"#4a8a48",
    t1:"#111110",t2:"#4A4844",t3:"#8A857D",
    inputBg:"#FEFDFB",shadow:"rgba(0,0,0,.08)",..._fonts,
  },
  brass: {
    bg:"#D4A059",panel:"#C89548",card:"#C08E42",b:"#A07630",b2:"#8a6530",
    ac:"#3A3328",ac2:"#1A1510",acb:"rgba(58,51,40,0.1)",
    teal:"#3A3328",teal2:"#1A1510",tbg:"rgba(58,51,40,0.1)",
    blue:"#3a4a6a",amber:"#3A3328",red:"#8B2020",green:"#2D6A2E",
    t1:"#1A1510",t2:"#2A2118",t3:"#4A3828",
    inputBg:"#C08E42",shadow:"rgba(0,0,0,.15)",..._fonts,
  },
  midnight: {
    bg:"#08090E",panel:"#0E1018",card:"#141620",b:"#1E2030",b2:"#282a3a",
    ac:"#9E7A3E",ac2:"#D4A059",acb:"rgba(212,160,89,0.06)",
    teal:"#D4A059",teal2:"#9E7A3E",tbg:"rgba(212,160,89,0.06)",
    blue:"#6b8cce",amber:"#e8b86d",red:"#c45c4f",green:"#7eb87c",
    t1:"#E8E4F0",t2:"#A0A0B8",t3:"#6A6A80",
    inputBg:"#0E1018",shadow:"rgba(0,0,0,.4)",..._fonts,
  },
  forge: {
    bg:"#121010",panel:"#1A1616",card:"#201C1C",b:"#302828",b2:"#3a3030",
    ac:"#B85C30",ac2:"#E07840",acb:"rgba(224,120,64,0.06)",
    teal:"#E07840",teal2:"#B85C30",tbg:"rgba(224,120,64,0.06)",
    blue:"#6b8cce",amber:"#E07840",red:"#D04040",green:"#7eb87c",
    t1:"#F0E8E0",t2:"#B8A898",t3:"#887868",
    inputBg:"#1A1616",shadow:"rgba(0,0,0,.4)",..._fonts,
  },
  vault: {
    bg:"#0A0C0A",panel:"#10140F",card:"#161A15",b:"#222820",b2:"#2a3228",
    ac:"#7A8A40",ac2:"#A0B060",acb:"rgba(160,176,96,0.06)",
    teal:"#A0B060",teal2:"#7A8A40",tbg:"rgba(160,176,96,0.06)",
    blue:"#6b8cce",amber:"#A0B060",red:"#c45c4f",green:"#7eb87c",
    t1:"#E0E8DC",t2:"#A8B0A0",t3:"#708068",
    inputBg:"#10140F",shadow:"rgba(0,0,0,.4)",..._fonts,
  },
  mono: {
    bg:"#0A0A09",panel:"#131312",card:"#1A1A18",b:"#282826",b2:"#323230",
    ac:"#A8A498",ac2:"#F5F0E8",acb:"rgba(245,240,232,0.05)",
    teal:"#F5F0E8",teal2:"#A8A498",tbg:"rgba(245,240,232,0.05)",
    blue:"#A8A498",amber:"#A8A498",red:"#c45c4f",green:"#A8A498",
    t1:"#F5F0E8",t2:"#B0ADA6",t3:"#787570",
    inputBg:"#131312",shadow:"rgba(0,0,0,.4)",..._fonts,
  },
  contrast: {
    bg:"#000000",panel:"#0A0A0A",card:"#141414",b:"#333333",b2:"#444444",
    ac:"#D4A059",ac2:"#FFB840",acb:"rgba(212,160,89,0.1)",
    teal:"#FFB840",teal2:"#D4A059",tbg:"rgba(255,184,64,0.1)",
    blue:"#60A5FA",amber:"#FFB840",red:"#FF4040",green:"#50E850",
    t1:"#FFFFFF",t2:"#CCCCCC",t3:"#888888",
    inputBg:"#0A0A0A",shadow:"rgba(0,0,0,.5)",..._fonts,
  },
  cream: {
    bg:"#F5F0E6",panel:"#FAF7F0",card:"#FAF7F0",b:"#D8D0C0",b2:"#C8C0B0",
    ac:"#3A3328",ac2:"#5A4A30",acb:"rgba(58,51,40,0.06)",
    teal:"#3A3328",teal2:"#5A4A30",tbg:"rgba(58,51,40,0.06)",
    blue:"#4a6a9e",amber:"#9e7a3e",red:"#b03030",green:"#4a8a48",
    t1:"#3A3328",t2:"#5A5040",t3:"#8A7D6D",
    inputBg:"#FAF7F0",shadow:"rgba(0,0,0,.08)",..._fonts,
  },
};

export const THEME_LIST = [
  { id:"dark",     label:"Dark",     bg:"#0a0a09", ac:"#d4a059" },
  { id:"paper",    label:"Paper",    bg:"#F5F3EE", ac:"#d4a059" },
  { id:"brass",    label:"Brass",    bg:"#D4A059", ac:"#3A3328" },
  { id:"cream",    label:"Cream",    bg:"#F5F0E6", ac:"#3A3328" },
  { id:"midnight", label:"Midnight", bg:"#08090E", ac:"#D4A059" },
  { id:"forge",    label:"Forge",    bg:"#121010", ac:"#E07840" },
  { id:"vault",    label:"Vault",    bg:"#0A0C0A", ac:"#A0B060" },
  { id:"mono",     label:"Mono",     bg:"#0A0A09", ac:"#F5F0E8" },
  { id:"contrast", label:"Contrast", bg:"#000000", ac:"#FFB840" },
];

export const WALLPAPERS = [
  { id:"none", label:"None" },
  {
    id:"01-field",
    label:"Commitment Field",
    css:"radial-gradient(120% 80% at 20% 10%, rgba(212,160,89,.26), rgba(10,10,9,0) 45%), linear-gradient(135deg, #0a0a09 0%, #111110 40%, #1a1712 100%)"
  },
  {
    id:"01-mark",
    label:"Mark",
    css:"linear-gradient(120deg, #08090E 0%, #12131b 50%, #1b1d29 100%)"
  },
  {
    id:"02-proof",
    label:"The Proof",
    css:"linear-gradient(135deg, #10140F 0%, #1a2117 50%, #273021 100%)"
  },
  {
    id:"03-veil",
    label:"The Veil",
    css:"linear-gradient(140deg, #121010 0%, #1d1515 45%, #2a1b1b 100%)"
  },
  {
    id:"04-formula",
    label:"The Formula",
    css:"linear-gradient(130deg, #0d1117 0%, #15202b 45%, #1f2a36 100%)"
  },
  {
    id:"05-library",
    label:"The Library",
    css:"linear-gradient(135deg, #181410 0%, #231c14 45%, #2f2618 100%)"
  },
  {
    id:"06-construct",
    label:"Construction",
    css:"linear-gradient(135deg, #0f1014 0%, #181a22 45%, #242734 100%)"
  },
];

// Legacy aliases
export const DARK = THEMES.dark;
export const LIGHT = THEMES.paper;

export function applyTheme(T) {
  const r = document.documentElement.style;
  Object.entries(T).forEach(([k,v]) => r.setProperty(`--${k}`, v));
  document.body.style.background = T.bg;
  document.body.style.color = T.t1;
}

export function applyWallpaper(id) {
  const wp = WALLPAPERS.find(w => w.id === id);
  if (!wp || id === "none") {
    document.body.style.backgroundImage = "";
    document.body.classList.remove("has-wallpaper");
    localStorage.removeItem("cc_wallpaper");
  } else {
    document.body.style.backgroundImage = wp.css || `url(${wp.url})`;
    document.body.style.backgroundSize = "cover";
    document.body.style.backgroundPosition = "center";
    document.body.style.backgroundAttachment = "fixed";
    document.body.classList.add("has-wallpaper");
    localStorage.setItem("cc_wallpaper", id);
  }
}
