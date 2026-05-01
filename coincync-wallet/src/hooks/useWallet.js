import { useState, useEffect, useCallback } from "react";
import { rpc, isWalletBackendAvailable } from "../utils/rpc";

export function useWallet() {
  const [balance, setBalance]   = useState({ total:"—", unlocked:"—", locked:"0.000000000000" });
  const [syncInfo, setSyncInfo] = useState({ height:0, chainHeight:0, syncPct:0 });
  const [peers, setPeers]       = useState({ peers:0 });
  const [fees, setFees]         = useState({ slow:"—", normal:"—", fast:"—", flash:"—" });
  const [rsaState, setRsaState] = useState({ root:"—", count:0, ivcSteps:0 });
  const [txs, setTxs]           = useState([]);
  const [loading, setLoading]   = useState(true);
  const [mining, setMining]     = useState({ is_mining:false, hashrate:0, blocks_found:0, threads:1 });
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState("");
  const [lastScanned, setLastScanned] = useState(null);

  const refresh = useCallback(async () => {
    if (!isWalletBackendAvailable()) {
      setLoading(false);
      return;
    }
    try {
      const results = await Promise.allSettled([
        rpc.getBalance(), rpc.getBlockHeight(), rpc.getPeerCount(),
        rpc.getTransactions(), rpc.getFeeEstimate(), rpc.getRsaState(),
        rpc.getMiningStats(),
      ]);

      const [bal, blk, prs, txData, fee, rsaSt, mineSt] = results.map(r =>
        r.status === "fulfilled" ? r.value : null
      );

      if (bal) setBalance(bal);
      if (blk) setSyncInfo(blk);
      if (prs) setPeers(prs);
      if (txData?.txs) setTxs(txData.txs);
      if (fee) setFees(fee);
      if (rsaSt) setRsaState(rsaSt);
      if (mineSt) setMining(mineSt);
    } catch (e) {
      console.error("Refresh error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const scanWallet = useCallback(async () => {
    if (!isWalletBackendAvailable()) {
      return "Wallet backend unavailable — use the desktop app (Tauri).";
    }
    setScanning(true);
    setScanResult("Scanning chain...");
    try {
      const result = await rpc.scanWallet();
      setScanResult(typeof result === "string" ? result : "Scan complete");
      setLastScanned(new Date());

      // Refresh everything after scan
      await new Promise(r => setTimeout(r, 300));
      const bal = await rpc.getBalance();
      if (bal) setBalance(bal);
      const txData = await rpc.getTransactions();
      if (txData?.txs) setTxs(txData.txs);

      return result;
    } catch (e) {
      const msg = "Scan failed: " + String(e);
      setScanResult(msg);
      return msg;
    } finally {
      setScanning(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10000);
    return () => clearInterval(t);
  }, [refresh]);

  return { balance, syncInfo, peers, fees, rsaState, txs, loading, mining, scanning, scanResult, lastScanned, refresh, scanWallet };
}
