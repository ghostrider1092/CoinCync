import { useEffect, useRef } from "react";
import { useTheme } from "./ui";
import QR from "qrcode";

export default function QRCode({ value, size=140 }) {
  const T = useTheme();
  const ref = useRef();

  useEffect(() => {
    if (!ref.current || !value) return;
    QR.toCanvas(ref.current, value, {
      width: size,
      margin: 2,
      color: { dark: "#d4a059", light: T.bg || "#1a1816" },
      errorCorrectionLevel: "M",
    }).catch(() => {
      const ctx = ref.current.getContext("2d");
      ctx.fillStyle = T.bg || "#1a1816";
      ctx.fillRect(0, 0, size, size);
      ctx.font = "10px monospace";
      ctx.fillStyle = T.t3;
      ctx.textAlign = "center";
      ctx.fillText("QR unavailable", size/2, size/2);
    });
  }, [value, size, T]);

  return <canvas ref={ref} width={size} height={size} style={{ borderRadius:8 }}/>;
}
