// WEBSOCKET REAL-TIME UPDATES
// Connects to the REST API WebSocket for push-based block/tx/status updates.
// Falls back to polling if WebSocket is unavailable.
//

let _ws = null;
let _wsRetryCount = 0;
const WS_MAX_RETRIES = 5;

function connectWebSocket(){
  // Build WS URL from current page origin, targeting REST API port (rpc+2)
  const loc = window.location;
  const port = parseInt(loc.port || (loc.protocol==='https:'?443:80));
  // Explorer is on rpc+1, REST API WS is on rpc+2
  const wsPort = port + 1;
  const wsProto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProto}//${loc.hostname}:${wsPort}/api/v1/ws`;

  try {
    _ws = new WebSocket(wsUrl);

    _ws.onopen = () => {
      _wsRetryCount = 0;
      console.log('WebSocket connected to', wsUrl);
    };

    _ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if(msg.type === 'new_block' && msg.data){
          // Trigger a poll to refresh all UI with the new block
          poll();
        }
        if(msg.type === 'mempool_update'){
          // Refresh mempool count in ticker
          const cnt = msg.data && msg.data.count;
          if(cnt != null){
            const el=$('tk-pool');if(el)el.textContent=cnt+' txs';
          }
        }
        if(msg.type === 'status' && msg.data){
          // Update anonymity set from WS heartbeat
          if(msg.data.anonymity_set != null){
            const el=$('aset-value');if(el)el.textContent=num(msg.data.anonymity_set);
          }
        }
      }catch(e){}
    };

    _ws.onclose = () => {
      _ws = null;
      if(_wsRetryCount < WS_MAX_RETRIES){
        _wsRetryCount++;
        setTimeout(connectWebSocket, 5000 * _wsRetryCount);
      }
    };

    _ws.onerror = () => { _ws && _ws.close(); };
  }catch(e){
    console.warn('WebSocket not available, using polling fallback');
  }
}

// Attempt WebSocket connection — DISABLED.
//
// The previous design pointed `wss://explorer.coincync.network:444` because
// the REST WebSocket lives on `rpc_port + 2` of the daemon. That port isn't
// exposed through Cloudflare's standard proxy, so the connection always
// failed and produced console-error noise on every page load.
//
// Tightening the polling cadence below to ~3-5s gives near-real-time UX
// without requiring port 444. If/when the REST WS is exposed properly via
// CF (Enterprise tier or a dedicated Spectrum rule), this can be re-enabled
// — the connectWebSocket() function is still present and will work the
// moment the port is reachable.
//
// setTimeout(connectWebSocket, 2000);  // re-enable when port 444 is proxied
