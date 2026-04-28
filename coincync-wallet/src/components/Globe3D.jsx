import { useEffect, useRef } from "react";
import { useTheme } from "./ui";

// High-quality canvas globe — no WebGL dependencies
// Matches the explorer's dark aesthetic with glowing nodes and arcs

const NODES = [
  { lat:40.71, lng:-74.01, label:"NYC", role:"Relay" },
  { lat:37.59, lng:-77.46, label:"RIC", role:"Explorer" },
  { lat:43.65, lng:-79.38, label:"TOR", role:"Relay" },
  { lat:33.75, lng:-84.39, label:"ATL", role:"Relay" },
  { lat:37.77, lng:-122.42, label:"SFO", role:"Relay" },
  { lat:51.51, lng:-0.13, label:"LON", role:"Miner" },
];

// Simplified continent coastlines (lat/lng point arrays)
const LAND = [
  // North America
  [[70,-165],[60,-140],[55,-130],[48,-125],[40,-124],[32,-117],[25,-110],[20,-105],[15,-92],[18,-88],[22,-85],[25,-80],[30,-82],[35,-75],[40,-74],[42,-70],[45,-66],[47,-63],[50,-56],[55,-60],[60,-65],[55,-80],[60,-95],[65,-90],[70,-100],[72,-130],[70,-165]],
  // South America
  [[12,-72],[10,-62],[5,-52],[0,-50],[-5,-35],[-10,-37],[-20,-40],[-30,-50],[-40,-65],[-55,-68],[-50,-75],[-42,-73],[-35,-72],[-20,-70],[-5,-78],[0,-78],[5,-77],[12,-72]],
  // Europe
  [[36,-6],[38,0],[43,5],[44,8],[46,3],[48,0],[48,-5],[52,-5],[55,-3],[58,0],[60,5],[63,10],[65,14],[68,16],[70,20],[70,28],[65,25],[60,25],[55,22],[55,15],[50,15],[50,20],[47,16],[44,12],[42,15],[40,25],[38,24],[36,28],[40,30],[42,28],[45,30],[42,35],[37,36],[36,0],[36,-6]],
  // Africa
  [[35,-5],[37,10],[33,12],[30,32],[25,35],[15,42],[10,44],[5,42],[0,42],[-5,40],[-10,40],[-15,35],[-25,33],[-30,30],[-34,26],[-34,18],[-28,15],[-15,12],[-5,12],[5,0],[5,-5],[10,-15],[15,-17],[20,-17],[25,-15],[30,-10],[35,-5]],
  // Asia (simplified)
  [[42,28],[45,40],[40,50],[35,55],[25,58],[25,65],[30,75],[28,85],[22,88],[20,92],[25,100],[22,105],[30,110],[35,115],[40,120],[45,135],[50,140],[55,140],[60,150],[65,170],[68,180],[72,140],[72,120],[68,90],[60,60],[55,50],[55,40],[50,40],[42,28]],
  // Australia
  [[-12,130],[-15,125],[-20,115],[-30,115],[-35,118],[-38,145],[-35,150],[-28,153],[-20,148],[-15,145],[-12,142],[-12,135],[-12,130]],
];

export default function Globe3D({ width=220, height=220 }) {
  const T = useTheme();
  const canvasRef = useRef(null);
  const frameRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const cx = width/2, cy = height/2, R = Math.min(width,height)/2 - 14;
    let angle = -0.5, time = 0;

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
      ctx.clearRect(0, 0, width, height);
      time += 0.016;

      // ── Atmosphere ──
      const atmo = ctx.createRadialGradient(cx, cy, R*0.9, cx, cy, R*1.2);
      atmo.addColorStop(0, "transparent");
      atmo.addColorStop(0.6, "rgba(34,214,140,0.03)");
      atmo.addColorStop(1, "transparent");
      ctx.fillStyle = atmo;
      ctx.fillRect(0, 0, width, height);

      // ── Globe body ──
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      const body = ctx.createRadialGradient(cx-R*0.25, cy-R*0.3, 0, cx, cy, R);
      body.addColorStop(0, "#162018");
      body.addColorStop(0.5, "#0e1510");
      body.addColorStop(1, "#060a08");
      ctx.fillStyle = body;
      ctx.fill();

      // ── Rim glow ──
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      ctx.strokeStyle = "rgba(34,214,140,0.12)";
      ctx.lineWidth = 2;
      ctx.stroke();

      // ── Grid ──
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
          ctx.strokeStyle = `rgba(34,214,140,${Math.abs(w)*0.05})`;
          ctx.lineWidth = 0.4;
          ctx.stroke();
        }
      }
      for (let i = 1; i < 9; i++) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, R, (i/9) * R, 0, 0, Math.PI*2);
        ctx.strokeStyle = "rgba(34,214,140,0.03)";
        ctx.lineWidth = 0.4;
        ctx.stroke();
      }

      // ── Continents ──
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
        // Land fill with depth-based opacity
        const avgZ = pts.reduce((a,p)=>a+p.z,0) / pts.length;
        const landOpacity = Math.max(0.02, (avgZ + 0.3) * 0.12);
        ctx.fillStyle = `rgba(34,214,140,${landOpacity})`;
        ctx.fill();
        ctx.strokeStyle = `rgba(34,214,140,${landOpacity * 2.5})`;
        ctx.lineWidth = 0.6;
        ctx.stroke();
      });

      // ── Connection arcs ──
      const projected = NODES.map(n => ({ ...n, ...project(n.lat, n.lng) }));
      const vis = projected.filter(n => n.z > 0);

      for (let i = 0; i < vis.length; i++) {
        for (let j = i+1; j < vis.length; j++) {
          const a = vis[i], b = vis[j];
          const mx = (a.x+b.x)/2, my = (a.y+b.y)/2;
          const dist = Math.hypot(a.x-b.x, a.y-b.y);
          const lift = -dist * 0.25;

          // Arc line
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.quadraticCurveTo(mx, my + lift, b.x, b.y);
          ctx.strokeStyle = `rgba(34,214,140,${Math.min(a.z, b.z) * 0.2})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();

          // Animated packet
          const t = ((time * 0.8 + i * 2 + j) % 3) / 3;
          const px = a.x*(1-t)*(1-t) + 2*mx*t*(1-t) + b.x*t*t;
          const py = a.y*(1-t)*(1-t) + 2*(my+lift)*t*(1-t) + b.y*t*t;
          ctx.beginPath();
          ctx.arc(px, py, 1.2, 0, Math.PI*2);
          ctx.fillStyle = `rgba(34,214,140,${0.7 * Math.min(a.z, b.z)})`;
          ctx.fill();
        }
      }

      // ── Nodes ──
      projected.forEach(node => {
        if (node.z < -0.05) return;
        const op = Math.max(0.15, (node.z + 0.05) / 1.05);
        const pulse = Math.sin(time * 2.5 + node.lat * 0.1) * 0.3 + 0.7;
        const isMiner = node.role === "Miner";
        const col = isMiner ? "240,192,64" : "34,214,140";

        // Pulse ring
        const ringR = 8 + Math.sin(time * 2 + node.lng) * 3;
        ctx.beginPath();
        ctx.arc(node.x, node.y, ringR, 0, Math.PI*2);
        ctx.strokeStyle = `rgba(${col},${op * 0.15 * pulse})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();

        // Glow
        const glow = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, 8);
        glow.addColorStop(0, `rgba(${col},${op * 0.5})`);
        glow.addColorStop(1, "transparent");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 8, 0, Math.PI*2);
        ctx.fill();

        // Dot
        ctx.beginPath();
        ctx.arc(node.x, node.y, 2.5, 0, Math.PI*2);
        ctx.fillStyle = `rgba(${col},${op})`;
        ctx.fill();

        // White center
        ctx.beginPath();
        ctx.arc(node.x, node.y, 1, 0, Math.PI*2);
        ctx.fillStyle = `rgba(255,255,255,${op * 0.7})`;
        ctx.fill();

        // Label
        if (node.z > 0.25) {
          ctx.font = `bold 7px 'JetBrains Mono',monospace`;
          ctx.fillStyle = `rgba(${col},${op * 0.95})`;
          ctx.fillText(node.label, node.x + 8, node.y - 4);
          ctx.font = `6px 'JetBrains Mono',monospace`;
          ctx.fillStyle = `rgba(200,200,200,${op * 0.4})`;
          ctx.fillText(node.role, node.x + 8, node.y + 4);
        }
      });

      ctx.restore();

      // ── Specular highlight ──
      const spec = ctx.createRadialGradient(cx-R*0.3, cy-R*0.35, 0, cx-R*0.3, cy-R*0.35, R*0.45);
      spec.addColorStop(0, "rgba(255,255,255,0.025)");
      spec.addColorStop(1, "transparent");
      ctx.fillStyle = spec;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI*2);
      ctx.fill();

      angle += 0.0015;
      frameRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(frameRef.current);
  }, [T, width, height]);

  return (
    <canvas ref={canvasRef}
      style={{ display:"block", width, height, borderRadius:14 }}/>
  );
}
