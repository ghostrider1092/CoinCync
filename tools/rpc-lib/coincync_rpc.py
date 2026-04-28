"""
CoinCync RPC Client — Python

Usage:
    from coincync_rpc import CoinCyncRPC

    node = CoinCyncRPC("http://127.0.0.1:28081")
    info = node.get_info()
    print(f"Height: {info['height']}, Peers: {info['peer_count']}")

    # With API key for wallet operations
    node = CoinCyncRPC("http://127.0.0.1:28081", api_key="your-key")
    balance = node.get_balance()
    node.transfer("tCYNC...", "10.5")
"""

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class CoinCyncRPCError(Exception):
    """RPC error with code and message."""
    def __init__(self, message: str, code: int = -1):
        super().__init__(message)
        self.code = code


class CoinCyncRPC:
    """JSON-RPC 2.0 client for CoinCync nodes."""

    def __init__(self, url: str = "http://127.0.0.1:28081",
                 api_key: Optional[str] = None,
                 timeout: int = 30):
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self._id = 0

    def _call(self, method: str, params: Optional[List] = None) -> Any:
        """Make a JSON-RPC call."""
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params or [],
        }).encode("utf-8")

        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise CoinCyncRPCError(f"Connection failed: {e}") from e
        except json.JSONDecodeError as e:
            raise CoinCyncRPCError(f"Invalid JSON response: {e}") from e

        if "error" in data and data["error"]:
            err = data["error"]
            raise CoinCyncRPCError(
                err.get("message", str(err)),
                err.get("code", -1),
            )

        return data.get("result")

    # ─── Node Info ───
    def get_info(self) -> Dict:
        """Get node status: height, peers, difficulty, version."""
        return self._call("get_info")

    def health(self) -> Dict:
        """Health check."""
        return self._call("health")

    def get_block_count(self) -> int:
        """Get current block height."""
        return self._call("get_block_count")

    def get_peers(self) -> Dict:
        """Get connected peers."""
        return self._call("get_peers")

    def get_supply_info(self) -> Dict:
        """Get supply data: emitted, burned, circulating."""
        return self._call("get_supply_info")

    def get_dandelion_stats(self) -> Dict:
        """Get Dandelion++ propagation stats."""
        return self._call("get_dandelion_stats")

    def get_metrics(self) -> Dict:
        """Get Prometheus metrics."""
        return self._call("get_metrics")

    # ─── Blockchain ───
    def get_block(self, block_hash: str) -> Dict:
        """Get block by hash."""
        return self._call("get_block", [block_hash])

    def get_block_by_height(self, height: int) -> Dict:
        """Get block by height."""
        return self._call("get_block_by_height", [height])

    def get_block_hash(self, height: int) -> str:
        """Get block hash at height."""
        return self._call("get_block_hash", [height])

    def get_transaction(self, tx_hash: str) -> Dict:
        """Get transaction by hash."""
        return self._call("get_transaction", [tx_hash])

    # ─── Mining ───
    def get_block_template(self, address: str) -> Dict:
        """Get mining block template."""
        return self._call("get_block_template", [address])

    def submit_block(self, block_hex: str) -> Dict:
        """Submit a mined block."""
        return self._call("submit_block", [block_hex])

    def get_mining_live(self) -> Dict:
        """Get live mining stats."""
        return self._call("get_mining_live")

    # ─── Mempool ───
    def get_tx_pool(self) -> Dict:
        """Get pending transactions."""
        return self._call("get_tx_pool")

    def submit_transaction(self, tx_hex: str) -> Dict:
        """Submit a signed transaction."""
        return self._call("submit_transaction", [tx_hex])

    # ─── Wallet (requires API key) ───
    def get_balance(self, api_key: Optional[str] = None) -> Dict:
        """Get wallet balance."""
        return self._call("get_balance", [api_key or self.api_key])

    def get_address(self, api_key: Optional[str] = None) -> Dict:
        """Get wallet address."""
        return self._call("get_address", [api_key or self.api_key])

    def transfer(self, address: str, amount: str,
                 api_key: Optional[str] = None) -> Dict:
        """Send CYNC to an address.

        Args:
            address: Recipient address (tCYNC...)
            amount: Amount in CYNC (e.g. "10.5")
            api_key: API key for authentication
        """
        return self._call("transfer", [address, amount, api_key or self.api_key])

    def estimate_fee(self, inputs: int = 1, outputs: int = 2) -> Dict:
        """Estimate transaction fee."""
        return self._call("estimate_fee", [inputs, outputs])

    def sweep_dust(self, api_key: Optional[str] = None) -> Dict:
        """Consolidate small UTXOs."""
        return self._call("sweep_dust", [api_key or self.api_key])

    def get_transfers(self, api_key: Optional[str] = None) -> Dict:
        """Get transaction history."""
        return self._call("get_transfers", [api_key or self.api_key])

    def get_outputs(self, api_key: Optional[str] = None) -> Dict:
        """Get wallet outputs/UTXOs."""
        return self._call("get_outputs", [api_key or self.api_key])

    # ─── Subaddresses ───
    def create_subaddress(self, label: str = "",
                          api_key: Optional[str] = None) -> Dict:
        """Create a new subaddress."""
        return self._call("create_subaddress", [label, api_key or self.api_key])

    def get_subaddresses(self, api_key: Optional[str] = None) -> Dict:
        """List all subaddresses."""
        return self._call("get_subaddresses", [api_key or self.api_key])

    # ─── Assets ───
    def get_asset_info(self, asset_id: str) -> Dict:
        """Get asset policy by ID."""
        return self._call("get_asset_info", [asset_id])

    def list_assets(self) -> Dict:
        """List all known assets."""
        return self._call("list_assets")

    def get_asset_balance(self, asset_id: str,
                          api_key: Optional[str] = None) -> Dict:
        """Get balance for a specific asset."""
        return self._call("get_asset_balance", [asset_id, api_key or self.api_key])

    # ─── Privacy ───
    def get_random_outputs(self, count: int = 11) -> Dict:
        """Get random outputs for ring signature decoys."""
        return self._call("get_random_outputs", [count])

    # ─── Faucet ───
    def faucet_request(self, address: str) -> Dict:
        """Request testnet coins from faucet (rate limited)."""
        return self._call("faucet_request", [address])

    # ─── Utility ───
    def get_sync_checkpoints(self) -> Dict:
        """Get chain sync checkpoints."""
        return self._call("get_sync_checkpoints")

    def get_pruning_info(self) -> Dict:
        """Get pruning status."""
        return self._call("get_pruning_info")

    def __repr__(self) -> str:
        return f"CoinCyncRPC(url='{self.url}')"


# ─── Quick test ───
if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28081"
    node = CoinCyncRPC(url)
    try:
        info = node.get_info()
        print(f"CoinCync Node v{info.get('version', '?')}")
        print(f"  Height:     {info.get('height', '?')}")
        print(f"  Peers:      {info.get('peer_count', '?')}")
        print(f"  Difficulty:  {info.get('difficulty', '?')}")
        print(f"  Network:    {info.get('network', '?')}")
        print(f"  Synced:     {info.get('synced', '?')}")
    except CoinCyncRPCError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Connection failed: {e}")
