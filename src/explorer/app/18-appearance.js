// THEME SYSTEM — 9 CoinCync brand themes
//
const THEMES = ['paper','dark','brass','cream','midnight','forge','vault','mono','contrast'];
const THEME_LABELS = {paper:'Paper',dark:'Dark',brass:'Brass',cream:'Cream',midnight:'Midnight',forge:'Forge',vault:'Vault',mono:'Mono',contrast:'Contrast'};
const DARK_THEMES = ['dark','midnight','forge','vault','mono','contrast'];
// Per-theme SVG icon for the pill thumb. Single-colour (currentColor)
// so the theme's --ac2 paints them. Designed for 14×14 — keep paths
// simple, avoid sub-pixel detail.
const THEME_ICONS = {
  paper:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 19 L19 5 M14 4 L20 10 M11 8 L16 13"/><path d="M5 19 L8 16"/></svg>',
  dark:     '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.5 13.4A8 8 0 0 1 10.6 4.5 8 8 0 1 0 19.5 13.4z"/></svg>',
  brass:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4" fill="currentColor"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>',
  cream:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>',
  midnight: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2 L13.5 9.5 L21 11 L13.5 12.5 L12 20 L10.5 12.5 L3 11 L10.5 9.5 Z"/></svg>',
  forge:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 22c-4 0-7-2.7-7-6.5 0-2.5 2-4 3-5.5C9 9 9 7 9 4c1 1 5 4 6 8 0 0 1-1 1-3 1.5 1.5 4 4 4 7.5 0 3.8-3 5.5-8 5.5z"/></svg>',
  vault:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.5 19.2 3c.6 4.5-1 12-9.2 16M2 22c1-4 5-8 9-9"/></svg>',
  mono:     '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="7"/></svg>',
  contrast: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3 A9 9 0 0 1 12 21 Z" fill="currentColor"/></svg>'
};

function renderThumbIcon(name) {
  const thumb = document.getElementById('theme-thumb');
  if (!thumb) return;
  thumb.innerHTML = THEME_ICONS[name] || THEME_ICONS.paper;
}

// Spin/fade swap animation: thumb rotates 360° + scales down + the icon
// cross-fades. JS swaps the SVG mid-fade so the user only ever sees the
// new icon emerge. ~420 ms total.
function animateThumbSwap(name) {
  const thumb = document.getElementById('theme-thumb');
  const label = document.getElementById('theme-label');
  if (!thumb) return;
  thumb.classList.remove('swap');
  if (label) label.classList.remove('swap');
  void thumb.offsetWidth; // force reflow so animation re-fires
  thumb.classList.add('swap');
  if (label) label.classList.add('swap');
  setTimeout(() => {
    renderThumbIcon(name);
    if (label) label.textContent = THEME_LABELS[name] || name;
  }, 180);
  setTimeout(() => {
    thumb.classList.remove('swap');
    if (label) label.classList.remove('swap');
  }, 440);
}

function setTheme(name, keepOpen, skipAnimation) {
  if (!THEMES.includes(name)) name = 'paper';
  const el = document.documentElement;
  el.classList.remove('dark');
  el.removeAttribute('data-theme');
  el.setAttribute('data-theme', name);
  if (DARK_THEMES.includes(name)) el.classList.add('dark');
  // Update picker UI — animate unless caller asks for an instant swap
  // (used at init so the page doesn't spin its own pill on every load).
  if (skipAnimation) {
    renderThumbIcon(name);
    const label = document.getElementById('theme-label');
    if (label) label.textContent = THEME_LABELS[name] || name;
  } else {
    animateThumbSwap(name);
  }
  document.querySelectorAll('.theme-opt').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-theme') === name);
  });
  if (!keepOpen) {
    const picker = document.getElementById('theme-picker');
    if (picker) picker.classList.remove('open');
  }
  localStorage.setItem('cync-theme', name);
}

function cycleTheme(dir) {
  const cur = document.documentElement.getAttribute('data-theme') || 'paper';
  const idx = THEMES.indexOf(cur);
  const next = (idx + dir + THEMES.length) % THEMES.length;
  setTheme(THEMES[next]);
}

//
// WALLPAPER SYSTEM
//
const WALLPAPERS = {
  'none':          { url: null, theme: null, label: 'None' },
  '01-field':      { url: 'assets/wallpapers/wallpaper-01-commitment-field-landscape.svg', theme: 'dark', label: 'Commitment Field' },
  '01-mark':       { url: 'assets/wallpapers/wallpaper-01-mark-landscape.svg', theme: 'dark', label: 'Mark' },
  '02-proof':      { url: 'assets/wallpapers/wallpaper-02-proof-landscape.svg', theme: 'dark', label: 'The Proof' },
  '02-lockup':     { url: 'assets/wallpapers/wallpaper-02-lockup-landscape.svg', theme: 'dark', label: 'Lockup' },
  '03-veil':       { url: 'assets/wallpapers/wallpaper-03-veil-landscape.svg', theme: 'dark', label: 'The Veil' },
  '03-reversed':   { url: 'assets/wallpapers/wallpaper-03-reversed-landscape.svg', theme: 'brass', label: 'Reversed' },
  '04-formula':    { url: 'assets/wallpapers/wallpaper-04-formula-landscape.svg', theme: 'dark', label: 'The Formula' },
  '04-mono':       { url: 'assets/wallpapers/wallpaper-04-mono-pair-landscape.svg', theme: 'mono', label: 'Mono Pair' },
  '05-library':    { url: 'assets/wallpapers/wallpaper-05-library-landscape.svg', theme: 'dark', label: 'The Library' },
  '05-specimen':   { url: 'assets/wallpapers/wallpaper-05-specimen-sheet-landscape.svg', theme: 'dark', label: 'Specimen' },
  '06-construct':  { url: 'assets/wallpapers/wallpaper-06-construction-landscape.svg', theme: 'dark', label: 'Construction' },
};

function setWallpaper(id, userClick) {
  const wp = WALLPAPERS[id];
  if (!wp) return;
  const body = document.body;
  const thumb = document.getElementById('theme-thumb');
  if (id === 'none' || !wp.url) {
    body.classList.remove('has-wallpaper');
    body.style.backgroundImage = '';
    if (thumb) { thumb.classList.remove('with-wp'); thumb.style.backgroundImage = ''; }
    localStorage.removeItem('cync-wallpaper');
  } else {
    body.classList.add('has-wallpaper');
    body.style.backgroundImage = 'url(' + wp.url + ')';
    // Tiny crop of the wallpaper SVG goes into the pill thumb so a
    // glance shows both active theme (icon) and active wallpaper (bg).
    if (thumb) { thumb.classList.add('with-wp'); thumb.style.backgroundImage = 'url(' + wp.url + ')'; }
    localStorage.setItem('cync-wallpaper', id);
    // Only auto-switch theme when user actively clicks a wallpaper,
    // not on page load restore (which would override their chosen theme)
    if (wp.theme && userClick) setTheme(wp.theme, true);
  }
  document.querySelectorAll('.wp-thumb').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-wp') === id);
  });
}

// Init wallpaper from localStorage
(function() {
  const saved = localStorage.getItem('cync-wallpaper');
  if (saved && WALLPAPERS[saved]) setWallpaper(saved);
})();

// Close theme picker on outside click
document.addEventListener('click', function(e) {
  const picker = document.getElementById('theme-picker');
  if (picker && !picker.contains(e.target)) picker.classList.remove('open');
});

//
// APPEARANCE PANEL (full-screen, works on mobile + desktop)
//
function openAppearance() {
  const o = document.getElementById('appear-overlay');
  if (o) { o.classList.add('open'); syncAppearanceState(); }
}
function closeAppearance() {
  const o = document.getElementById('appear-overlay');
  if (o) o.classList.remove('open');
}
function markApTheme(name) {
  document.querySelectorAll('.ap-theme').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-theme') === name);
  });
}
function markApWall(id) {
  document.querySelectorAll('.ap-wall').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-wp') === id);
  });
}
function syncAppearanceState() {
  const t = document.documentElement.getAttribute('data-theme') || 'paper';
  markApTheme(t);
  const w = localStorage.getItem('cync-wallpaper') || 'none';
  markApWall(w);
}

// Init: load saved theme or auto-detect.
// skipAnimation=true so the page doesn't spin its own pill on every
// page load; the swap animation is reserved for active user clicks.
(function() {
  const saved = localStorage.getItem('cync-theme');
  if (saved && THEMES.includes(saved)) {
    setTheme(saved, true, true);
  } else if (localStorage.getItem('cync-dark') === '1') {
    // Migration from old dark mode toggle
    setTheme('dark', true, true);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    setTheme('dark', true, true);
  } else {
    setTheme('paper', true, true);
  }
})();

//
// UNIVERSAL COPY HELPER (#3)
//
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    if (btn) { btn.classList.add('copied'); btn.textContent = '✓ copied'; setTimeout(() => { btn.classList.remove('copied'); btn.textContent = '📋 copy'; }, 2000); }
    showToast('📋', 'Copied', text.slice(0, 24) + '...', 2000);
  });
}

//
