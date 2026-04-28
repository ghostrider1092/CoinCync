import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("CoinCync Wallet Error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ height:"100vh", display:"flex", flexDirection:"column",
          alignItems:"center", justifyContent:"center", background:"#1a1816",
          color:"#F2F0EC", padding:40, textAlign:"center" }}>
          <div style={{ fontSize:48, marginBottom:16 }}>&#9888;</div>
          <h1 style={{ fontFamily:"Georgia,serif", fontSize:24, fontWeight:400, marginBottom:8 }}>
            Something went wrong
          </h1>
          <p style={{ fontSize:12, color:"#A09A90", marginBottom:20, maxWidth:400, lineHeight:1.6 }}>
            The wallet encountered an error. Your funds are safe — this is a display issue only.
            Your seed phrase and wallet file are not affected.
          </p>
          <div style={{ background:"#252320", border:"1px solid #2e2c2a", borderRadius:8,
            padding:"10px 14px", fontSize:10, color:"#EF4444", fontFamily:"monospace",
            maxWidth:500, wordBreak:"break-all", marginBottom:20, textAlign:"left" }}>
            {this.state.error?.message || "Unknown error"}
          </div>
          <button onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}
            style={{ background:"linear-gradient(135deg, #d4a059, #9e7a3e)", color:"#fff",
              border:"none", borderRadius:10, padding:"10px 24px", fontSize:13, fontWeight:700,
              cursor:"pointer" }}>
            Reload Wallet
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
