import { useState, useCallback, useRef } from "react";

let _id = 0;
const MAX_NOTIFS = 5;

export function useNotifications() {
  const [notifs, setNotifs] = useState([]);
  const lastPush = useRef(0);

  const push = useCallback((message, type="info", duration=4000) => {
    // Rate limit: ignore duplicate messages within 500ms
    const now = Date.now();
    if (now - lastPush.current < 500) return;
    lastPush.current = now;

    const id = ++_id;
    setNotifs(n => {
      const next = [...n, { id, message, type }];
      // Trim to max stack size
      return next.length > MAX_NOTIFS ? next.slice(-MAX_NOTIFS) : next;
    });
    setTimeout(() => setNotifs(n => n.filter(x => x.id !== id)), duration);
  }, []);

  const dismiss = useCallback(id => setNotifs(n => n.filter(x => x.id !== id)), []);
  return { notifs, push, dismiss };
}
