import { useRef, useEffect } from "react";
import { useTheme } from "./ui";

export default function BalanceChart({ data=[], width=400, height=120 }) {
  const T = useTheme();
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || data.length < 2) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const pad = { top:10, right:10, bottom:24, left:50 };
    const w = width - pad.left - pad.right;
    const h = height - pad.top - pad.bottom;

    const vals = data.map(d => d.value);
    const maxVal = Math.max(...vals) * 1.1 || 1;
    const minVal = Math.min(...vals) * 0.9;
    const range = maxVal - minVal || 1;

    ctx.clearRect(0, 0, width, height);

    // Grid lines
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (i/4) * h;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + w, y);
      ctx.strokeStyle = T.b + "40";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      const val = maxVal - (i/4) * range;
      ctx.font = "9px 'JetBrains Mono',monospace";
      ctx.fillStyle = T.t3;
      ctx.textAlign = "right";
      ctx.fillText(val.toFixed(0), pad.left - 6, y + 3);
    }

    // Gradient fill — use theme accent
    const ac = T.ac2 || "#d4a059";
    const r = parseInt(ac.slice(1,3),16), g = parseInt(ac.slice(3,5),16), b2 = parseInt(ac.slice(5,7),16);
    const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + h);
    gradient.addColorStop(0, `rgba(${r},${g},${b2},0.15)`);
    gradient.addColorStop(1, `rgba(${r},${g},${b2},0.01)`);

    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top + h);
    data.forEach((d, i) => {
      const x = pad.left + (i / (data.length - 1)) * w;
      const y = pad.top + h - ((d.value - minVal) / range) * h;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(pad.left + w, pad.top + h);
    ctx.lineTo(pad.left, pad.top + h);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((d, i) => {
      const x = pad.left + (i / (data.length - 1)) * w;
      const y = pad.top + h - ((d.value - minVal) / range) * h;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = ac;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();

    // Current value dot
    const lastX = pad.left + w;
    const lastY = pad.top + h - ((vals[vals.length-1] - minVal) / range) * h;
    ctx.beginPath();
    ctx.arc(lastX, lastY, 4, 0, Math.PI*2);
    ctx.fillStyle = ac;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(lastX, lastY, 2, 0, Math.PI*2);
    ctx.fillStyle = "#fff";
    ctx.fill();

    // Labels
    ctx.font = "8px 'JetBrains Mono',monospace";
    ctx.fillStyle = T.t3;
    ctx.textAlign = "center";
    const labelIndices = [0, Math.floor(data.length/2), data.length-1];
    labelIndices.forEach(i => {
      if (data[i]?.label) {
        const x = pad.left + (i / (data.length - 1)) * w;
        ctx.fillText(data[i].label, x, height - 4);
      }
    });

  }, [data, width, height, T]);

  if (data.length < 2) {
    return (
      <div style={{ width, height, display:"flex", alignItems:"center", justifyContent:"center",
        background:T.bg, borderRadius:8, border:`1px solid ${T.b}`, fontSize:10, color:T.t3 }}>
        Scan wallet to see balance history
      </div>
    );
  }

  return <canvas ref={canvasRef} style={{ display:"block", width, height, borderRadius:8 }}/>;
}
