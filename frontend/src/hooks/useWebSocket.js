import { useState, useEffect, useRef } from "react";

export default function useWebSocket(url) {
  const [lastMessage, setLastMessage] = useState(null);
  const ws = useRef(null);

  useEffect(() => {
    const connect = () => {
      try {
        ws.current = new WebSocket(url);
        ws.current.onmessage = (e) => {
          try { setLastMessage(JSON.parse(e.data)); } catch {}
        };
        ws.current.onclose = () => {
          setTimeout(connect, 3000); // reconnect
        };
      } catch {}
    };
    connect();
    return () => ws.current?.close();
  }, [url]);

  return { lastMessage };
}
