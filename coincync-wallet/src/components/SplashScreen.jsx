import { useEffect, useRef, useState } from "react";
import { CoinLogo } from "./ui";

const NODES = [
  { lat:51.51, lng:-0.13,   label:"LON", role:"Miner" },
  { lat:37.77, lng:-122.42, label:"SFO", role:"Miner" },
  { lat:40.71, lng:-74.01,  label:"NYC", role:"Mempool" },
  { lat:50.11, lng:8.68,    label:"FRA", role:"Mempool" },
  { lat:43.70, lng:-79.42,  label:"TOR", role:"Seed" },
  { lat:37.54, lng:-77.43,  label:"RIC", role:"Explorer" },
  { lat:33.75, lng:-84.39,  label:"ATL", role:"RPC" },
  { lat:52.37, lng:4.90,    label:"AMS", role:"Seed" },
  { lat:40.73, lng:-73.99,  label:"NYC3",role:"Seed" },
];

const LAND = [
  [[70,-165],[60,-140],[55,-130],[48,-125],[40,-124],[32,-117],[25,-110],[20,-105],[15,-92],[18,-88],[22,-85],[25,-80],[30,-82],[35,-75],[40,-74],[42,-70],[45,-66],[47,-63],[50,-56],[55,-60],[60,-65],[55,-80],[60,-95],[65,-90],[70,-100],[72,-130],[70,-165]],
  [[12,-72],[10,-62],[5,-52],[0,-50],[-5,-35],[-10,-37],[-20,-40],[-30,-50],[-40,-65],[-55,-68],[-50,-75],[-42,-73],[-35,-72],[-20,-70],[-5,-78],[0,-78],[5,-77],[12,-72]],
  [[36,-6],[38,0],[43,5],[44,8],[46,3],[48,0],[48,-5],[52,-5],[55,-3],[58,0],[60,5],[63,10],[65,14],[68,16],[70,20],[70,28],[65,25],[60,25],[55,22],[55,15],[50,15],[50,20],[47,16],[44,12],[42,15],[40,25],[38,24],[36,28],[40,30],[42,28],[45,30],[42,35],[37,36],[36,0],[36,-6]],
  [[35,-5],[37,10],[33,12],[30,32],[25,35],[15,42],[10,44],[5,42],[0,42],[-5,40],[-10,40],[-15,35],[-25,33],[-30,30],[-34,26],[-34,18],[-28,15],[-15,12],[-5,12],[5,0],[5,-5],[10,-15],[15,-17],[20,-17],[25,-15],[30,-10],[35,-5]],
  [[42,28],[45,40],[40,50],[35,55],[25,58],[25,65],[30,75],[28,85],[22,88],[20,92],[25,100],[22,105],[30,110],[35,115],[40,120],[45,135],[50,140],[55,140],[60,150],[65,170],[68,180],[72,140],[72,120],[68,90],[60,60],[55,50],[55,40],[50,40],[42,28]],
  [[-12,130],[-15,125],[-20,115],[-30,115],[-35,118],[-38,145],[-35,150],[-28,153],[-20,148],[-15,145],[-12,142],[-12,135],[-12,130]],
];

export default function SplashScreen({ onComplete }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(0);
  const [phase, setPhase] = useState(0); // 0=globe only, 1=logo appears, 2=text appears, 3=nodes flash, 4=fade out
  const [opacity, setOpacity] = useState(1);
  const [nodesVisible, setNodesVisible] = useState(0);
  const startTime = useRef(Date.now());

  // Phase timing
  useEffect(() => {
    const timers = [
      setTimeout(() => setPhase(1), 800),    // Logo fades in
      setTimeout(() => setPhase(2), 1600),   // Title text
      setTimeout(() => setPhase(3), 2200),   // Nodes start appearing
      setTimeout(() => setPhase(4), 4200),   // Begin fade out
      setTimeout(() => {
        setOpacity(0);
        setTimeout(() => onComplete(), 600);
      }, 4500),
    ];
    return () => timers.forEach(clearTimeout);
  }, [onComplete]);

  // Nodes appear one by one
  useEffect(() => {
    if (phase < 3) return;
    const interval = setInterval(() => {
      setNodesVisible(v => {
        if (v >= NODES.length) { clearInterval(interval); return v; }
        return v + 1;
      });
    }, 120);
    return () => clearInterval(interval);
  }, [phase]);

  // Globe animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W = 360, H = 360;
    canvas.width = W * dpr; canvas.height = H * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const cx = W/2, cy = H/2, R = 155;
    let angle = -0.3, time = 0;

    function project(lat, lng) {
      const lr = lat * Math.PI / 180;
      const lo = (lng * Math.PI / 180) + angle;
      return {
        x: cx + R * Math.cos(lr) * Math.sin(lo),
        y: cy - R * Math.sin(lr),
        z: Math.cos(lr) * Math.cos(lo),
      };
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      time += 0.016;

      // Atmosphere
      const atmo = ctx.createRadialGradient(cx, cy, R*0.85, cx, cy, R*1.25);
      atmo.addColorStop(0, "transparent");
      atmo.addColorStop(0.5, "rgba(34,214,140,0.04)");
      atmo.addColorStop(0.8, "rgba(34,214,140,0.02)");
      atmo.addColorStop(1, "transparent");
      ctx.fillStyle = atmo;
      ctx.fillRect(0, 0, W, H);

      // Globe body
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      const body = ctx.createRadialGradient(cx-R*0.25, cy-R*0.3, 0, cx, cy, R);
      body.addColorStop(0, "#162018");
      body.addColorStop(0.5, "#0e1510");
      body.addColorStop(1, "#060a08");
      ctx.fillStyle = body;
      ctx.fill();

      // Rim
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      ctx.strokeStyle = "rgba(34,214,140,0.15)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Grid
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      ctx.clip();

      for (let i = 0; i < 18; i++) {
        const lo = (i/18) * Math.PI * 2 + angle;
        const w = Math.cos(lo);
        if (Math.abs(w) > 0.05) {
          ctx.beginPath();
          ctx.ellipse(cx, cy, Math.abs(w) * R, R, 0, 0, Math.PI*2);
          ctx.strokeStyle = `rgba(34,214,140,${Math.abs(w)*0.04})`;
          ctx.lineWidth = 0.4;
          ctx.stroke();
        }
      }
      for (let i = 1; i < 9; i++) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, R, (i/9) * R, 0, 0, Math.PI*2);
        ctx.strokeStyle = "rgba(34,214,140,0.025)";
        ctx.lineWidth = 0.4;
        ctx.stroke();
      }

      // Continents
      LAND.forEach(coast => {
        const pts = coast.map(([lat,lng]) => project(lat, lng));
        const visible = pts.filter(p => p.z > -0.15).length;
        if (visible < pts.length * 0.3) return;
        ctx.beginPath();
        let started = false;
        pts.forEach(p => {
          if (p.z > -0.15) {
            if (!started) { ctx.moveTo(p.x, p.y); started = true; }
            else ctx.lineTo(p.x, p.y);
          }
        });
        ctx.closePath();
        const avgZ = pts.reduce((a,p)=>a+p.z,0) / pts.length;
        const landOp = Math.max(0.02, (avgZ + 0.3) * 0.12);
        ctx.fillStyle = `rgba(34,214,140,${landOp})`;
        ctx.fill();
        ctx.strokeStyle = `rgba(34,214,140,${landOp * 2.5})`;
        ctx.lineWidth = 0.6;
        ctx.stroke();
      });

      // Connection arcs
      const projected = NODES.map(n => ({ ...n, ...project(n.lat, n.lng) }));
      const vis = projected.filter(n => n.z > 0);
      for (let i = 0; i < vis.length; i++) {
        for (let j = i+1; j < vis.length; j++) {
          const a = vis[i], b = vis[j];
          const mx = (a.x+b.x)/2, my = (a.y+b.y)/2;
          const dist = Math.hypot(a.x-b.x, a.y-b.y);
          const lift = -dist * 0.25;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.quadraticCurveTo(mx, my + lift, b.x, b.y);
          ctx.strokeStyle = `rgba(34,214,140,${Math.min(a.z, b.z) * 0.15})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();

          // Animated packet
          const t = ((time * 0.8 + i * 2 + j) % 3) / 3;
          const px = a.x*(1-t)*(1-t) + 2*mx*t*(1-t) + b.x*t*t;
          const py = a.y*(1-t)*(1-t) + 2*(my+lift)*t*(1-t) + b.y*t*t;
          ctx.beginPath();
          ctx.arc(px, py, 1, 0, Math.PI*2);
          ctx.fillStyle = `rgba(34,214,140,${0.5 * Math.min(a.z, b.z)})`;
          ctx.fill();
        }
      }

      // Nodes
      projected.forEach(node => {
        if (node.z < -0.05) return;
        const op = Math.max(0.15, (node.z + 0.05) / 1.05);
        const isMiner = node.role === "Miner";
        const col = isMiner ? "240,192,64" : "34,214,140";

        // Pulse
        const ringR = 6 + Math.sin(time * 2 + node.lng) * 2;
        ctx.beginPath();
        ctx.arc(node.x, node.y, ringR, 0, Math.PI*2);
        ctx.strokeStyle = `rgba(${col},${op * 0.12})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();

        // Glow
        const glow = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, 7);
        glow.addColorStop(0, `rgba(${col},${op * 0.4})`);
        glow.addColorStop(1, "transparent");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 7, 0, Math.PI*2);
        ctx.fill();

        // Dot
        ctx.beginPath();
        ctx.arc(node.x, node.y, 2.5, 0, Math.PI*2);
        ctx.fillStyle = `rgba(${col},${op})`;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(node.x, node.y, 1, 0, Math.PI*2);
        ctx.fillStyle = `rgba(255,255,255,${op * 0.6})`;
        ctx.fill();

        // Label
        if (node.z > 0.25) {
          ctx.font = "bold 7px 'JetBrains Mono',monospace";
          ctx.fillStyle = `rgba(${col},${op * 0.9})`;
          ctx.fillText(node.label, node.x + 7, node.y - 3);
          ctx.font = "6px 'JetBrains Mono',monospace";
          ctx.fillStyle = `rgba(200,200,200,${op * 0.35})`;
          ctx.fillText(node.role, node.x + 7, node.y + 5);
        }
      });

      ctx.restore();

      // Specular
      const spec = ctx.createRadialGradient(cx-R*0.3, cy-R*0.35, 0, cx-R*0.3, cy-R*0.35, R*0.4);
      spec.addColorStop(0, "rgba(255,255,255,0.02)");
      spec.addColorStop(1, "transparent");
      ctx.fillStyle = spec;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      ctx.fill();

      angle += 0.003;
      frameRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(frameRef.current);
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 100000,
      background: "#080c0a",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      opacity, transition: "opacity 0.6s ease",
    }}>
      {/* Subtle background gradient */}
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse at 50% 40%, rgba(34,214,140,0.04) 0%, transparent 70%)",
      }} />

      {/* Globe */}
      <div style={{
        position: "relative", zIndex: 1,
        transform: `scale(${phase >= 1 ? 0.85 : 1})`,
        transition: "transform 0.8s ease",
        marginBottom: -20,
      }}>
        <canvas ref={canvasRef} style={{ display: "block", width: 360, height: 360 }} />
      </div>

      {/* Logo + Text */}
      <div style={{
        position: "relative", zIndex: 2,
        textAlign: "center",
        opacity: phase >= 1 ? 1 : 0,
        transform: `translateY(${phase >= 1 ? 0 : 20}px)`,
        transition: "opacity 0.6s ease, transform 0.6s ease",
      }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "center", gap: 14,
          marginBottom: 8,
        }}>
          <div style={{ opacity: phase >= 1 ? 1 : 0, transition: "opacity 0.4s ease" }}>
            <CoinLogo size={44} />
          </div>
          <div style={{
            fontSize: 32, fontWeight: 400, letterSpacing: -1,
            color: "#f5f0e8", fontFamily: "'Fraunces',Georgia,serif",
          }}>
            Coin<span style={{ color: "#d4a059" }}>Cync</span>
          </div>
        </div>

        <div style={{
          fontFamily: "Georgia,'Times New Roman',serif",
          fontStyle: "italic", fontSize: 14,
          color: "#d4a059", letterSpacing: 0.5,
          opacity: phase >= 2 ? 1 : 0,
          transform: `translateY(${phase >= 2 ? 0 : 10}px)`,
          transition: "opacity 0.5s ease 0.1s, transform 0.5s ease 0.1s",
        }}>
          Privacy money that requires no permission.
        </div>
      </div>

      {/* Node status indicators */}
      <div style={{
        position: "relative", zIndex: 2,
        display: "flex", gap: 6, marginTop: 28,
        opacity: phase >= 3 ? 1 : 0,
        transition: "opacity 0.4s ease",
      }}>
        {NODES.map((node, i) => (
          <div key={node.label} style={{
            display: "flex", alignItems: "center", gap: 4,
            padding: "3px 8px", borderRadius: 6,
            background: i < nodesVisible ? "rgba(34,214,140,0.1)" : "rgba(255,255,255,0.03)",
            border: `1px solid ${i < nodesVisible ? "rgba(34,214,140,0.2)" : "rgba(255,255,255,0.05)"}`,
            transition: "all 0.3s ease",
          }}>
            <div style={{
              width: 5, height: 5, borderRadius: "50%",
              background: i < nodesVisible ? (node.role === "Miner" ? "#F0C040" : "#d4a059") : "#333",
              boxShadow: i < nodesVisible ? `0 0 4px ${node.role === "Miner" ? "#F0C040" : "#d4a059"}` : "none",
              transition: "all 0.3s ease",
            }} />
            <span style={{
              fontSize: 8, fontFamily: "'JetBrains Mono',monospace",
              color: i < nodesVisible ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.2)",
              fontWeight: 600, letterSpacing: 0.5,
              transition: "color 0.3s ease",
            }}>
              {node.label}
            </span>
          </div>
        ))}
      </div>

      {/* Bottom credit */}
      <div style={{
        position: "absolute", bottom: 32,
        textAlign: "center",
        opacity: phase >= 2 ? 0.4 : 0,
        transition: "opacity 0.8s ease",
      }}>
        <div style={{
          fontSize: 10, color: "rgba(255,255,255,0.5)",
          fontFamily: "'JetBrains Mono',monospace",
          letterSpacing: 1.5, textTransform: "uppercase",
        }}>
          Developed by
        </div>
        <div style={{
          fontSize: 13, color: "rgba(255,255,255,0.6)",
          fontFamily: "'Inter',system-ui,sans-serif",
          fontWeight: 600, marginTop: 4, letterSpacing: 0.3,
        }}>
          Cync Lab
        </div>
        <div style={{
          fontSize: 10, color: "rgba(255,255,255,0.3)",
          fontFamily: "Georgia,serif", fontStyle: "italic",
          marginTop: 3,
        }}>
          Applied cryptography for financial privacy
        </div>
      </div>

      {/* Version */}
      <div style={{
        position: "absolute", bottom: 12, right: 16,
        fontSize: 9, color: "rgba(255,255,255,0.15)",
        fontFamily: "'JetBrains Mono',monospace",
      }}>
        v1.0.1 testnet
      </div>
    </div>
  );
}
