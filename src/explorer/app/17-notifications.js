// TOAST NOTIFICATIONS (#16)
//
function showToast(icon, title, sub, duration=5000) {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = `<span class="toast-icon">${icon}</span><div class="toast-body"><div class="toast-title">${title}</div><div class="toast-sub">${sub}</div></div>`;
  c.appendChild(t);
  setTimeout(() => { t.classList.add('fade-out'); setTimeout(() => t.remove(), 300); }, duration);
}

// Block notification sound (#17)
let _soundEnabled = localStorage.getItem('cync-sound') === '1';
// (Sound is generated on-demand via `new AudioContext()` inside playBlockSound;
//  the legacy `_blockSound = new AudioContext ? null : null` placeholder was
//  dead code — the ternary always evaluated to `null`. Removed in v1.0.10.)
function playBlockSound() {
  if (!_soundEnabled) return;
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = 880; osc.type = 'sine';
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.start(); osc.stop(ctx.currentTime + 0.3);
  } catch(e) {}
}

// Hook into poll to detect new blocks
let _lastNotifiedHeight = 0;
const _origPoll = poll;
// Monkey-patch poll to add toast on new block (non-invasive)
(function() {
  const origUpdateFeed = updateLiveFeed;
  window.updateLiveFeed = async function(h) {
    await origUpdateFeed(h);
    if (_lastNotifiedHeight > 0 && h > _lastNotifiedHeight) {
      showToast('', `Block #${num(h)} mined`, `${h - _lastNotifiedHeight} new block${h-_lastNotifiedHeight>1?'s':''}`);
      playBlockSound();
      trackPropagation(h);
      notifyBlockListeners(h, '');
      // Update live stream feed
      const feed = document.getElementById('stream-feed');
      if (feed) {
        const entry = document.createElement('div');
        entry.className = 'live-feed-item new';
        entry.innerHTML = `<span class="blk-num">Block #${num(h)}</span><span class="blk-age">${new Date().toLocaleTimeString()}</span>`;
        if (feed.firstChild && feed.firstChild.style) feed.insertBefore(entry, feed.firstChild);
        else feed.innerHTML = '';
        feed.insertBefore(entry, feed.firstChild);
        const sc = document.getElementById('stream-count');
        if (sc) sc.textContent = feed.children.length + ' events';
      }
    }
    _lastNotifiedHeight = h;
  };
})();

//
// KEYBOARD SHORTCUTS (#10)
//
document.addEventListener('keydown', function(e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
  const key = e.key.toLowerCase();
  switch(key) {
    case 'h': go('home'); break;
    case 'b': go('blocks'); break;
    case 'n': go('network'); break;
    case 'm': go('mempool'); break;
    case 's': go('supply'); break;
    case '/': e.preventDefault(); const sq=document.getElementById('nav-q'); if(sq){sq.focus();} break;
    case 'd': { const dk=['dark','midnight','forge','vault','mono','contrast']; const cur=document.documentElement.getAttribute('data-theme')||'paper'; setTheme(dk.includes(cur)?'paper':'dark'); break; }
    case '?': document.getElementById('kbd-overlay').classList.toggle('show'); break;
    case 'escape': document.getElementById('kbd-overlay').classList.remove('show'); break;
    case 't': cycleTheme(1); break;
  }
  if (e.key === 'T') { cycleTheme(-1); }
});

//
