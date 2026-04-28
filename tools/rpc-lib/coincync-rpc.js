/**
 * CoinCync RPC Client — JavaScript/Node.js
 *
 * Usage (Node.js):
 *   const CoinCyncRPC = require('./coincync-rpc');
 *   const node = new CoinCyncRPC('http://127.0.0.1:28081');
 *   const info = await node.getInfo();
 *
 * Usage (Browser):
 *   <script src="coincync-rpc.js"></script>
 *   const node = new CoinCyncRPC('https://api.coincync.network/rpc');
 *   const info = await node.getInfo();
 */

class CoinCyncRPC {
  constructor(url = 'http://127.0.0.1:28081', options = {}) {
    this.url = url;
    this.timeout = options.timeout || 30000;
    this.apiKey = options.apiKey || null;
    this._id = 0;
  }

  async _call(method, params = []) {
    this._id++;
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: this._id,
      method: method,
      params: params,
    });

    const headers = { 'Content-Type': 'application/json' };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(this.url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);

      const data = await resp.json();
      if (data.error) {
        const err = new Error(data.error.message || JSON.stringify(data.error));
        err.code = data.error.code;
        throw err;
      }
      return data.result;
    } finally {
      clearTimeout(timer);
    }
  }

  // ─── Node Info ───
  async getInfo() { return this._call('get_info'); }
  async health() { return this._call('health'); }
  async getBlockCount() { return this._call('get_block_count'); }
  async getPeers() { return this._call('get_peers'); }
  async getSupplyInfo() { return this._call('get_supply_info'); }
  async getDandelionStats() { return this._call('get_dandelion_stats'); }
  async getMetrics() { return this._call('get_metrics'); }

  // ─── Blockchain ───
  async getBlock(hash) { return this._call('get_block', [hash]); }
  async getBlockByHeight(height) { return this._call('get_block_by_height', [height]); }
  async getBlockHash(height) { return this._call('get_block_hash', [height]); }
  async getTransaction(hash) { return this._call('get_transaction', [hash]); }

  // ─── Mining ───
  async getBlockTemplate(address) { return this._call('get_block_template', [address]); }
  async submitBlock(blockHex) { return this._call('submit_block', [blockHex]); }
  async getMiningLive() { return this._call('get_mining_live'); }

  // ─── Mempool ───
  async getTxPool() { return this._call('get_tx_pool'); }
  async submitTransaction(txHex) { return this._call('submit_transaction', [txHex]); }

  // ─── Wallet (requires API key) ───
  async getBalance(apiKey) { return this._call('get_balance', [apiKey || this.apiKey]); }
  async getAddress(apiKey) { return this._call('get_address', [apiKey || this.apiKey]); }
  async transfer(address, amount, apiKey) {
    return this._call('transfer', [address, amount, apiKey || this.apiKey]);
  }
  async estimateFee(inputs = 1, outputs = 2) {
    return this._call('estimate_fee', [inputs, outputs]);
  }
  async sweepDust(apiKey) { return this._call('sweep_dust', [apiKey || this.apiKey]); }
  async getTransfers(apiKey) { return this._call('get_transfers', [apiKey || this.apiKey]); }
  async getOutputs(apiKey) { return this._call('get_outputs', [apiKey || this.apiKey]); }

  // ─── Subaddresses ───
  async createSubaddress(label, apiKey) {
    return this._call('create_subaddress', [label, apiKey || this.apiKey]);
  }
  async getSubaddresses(apiKey) {
    return this._call('get_subaddresses', [apiKey || this.apiKey]);
  }

  // ─── Assets ───
  async getAssetInfo(assetId) { return this._call('get_asset_info', [assetId]); }
  async listAssets() { return this._call('list_assets'); }
  async getAssetBalance(assetId, apiKey) {
    return this._call('get_asset_balance', [assetId, apiKey || this.apiKey]);
  }

  // ─── Privacy ───
  async getRandomOutputs(count = 11) { return this._call('get_random_outputs', [count]); }

  // ─── Faucet ───
  async faucetRequest(address) { return this._call('faucet_request', [address]); }

  // ─── Utility ───
  async getSyncCheckpoints() { return this._call('get_sync_checkpoints'); }
  async getPruningInfo() { return this._call('get_pruning_info'); }
}

// CommonJS / ES module / Browser global
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CoinCyncRPC;
} else if (typeof window !== 'undefined') {
  window.CoinCyncRPC = CoinCyncRPC;
}
