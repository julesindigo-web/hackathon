import { useState, useEffect, useCallback } from 'react';

interface UseWebSocketOptions {
  url: string;
  onMessage?: (data: any) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export function useWebSocket({
  url,
  onMessage,
  reconnectInterval = 3000,
  maxReconnectAttempts = 5,
}: UseWebSocketOptions) {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);

  const connect = useCallback(() => {
    if (reconnectAttempts >= maxReconnectAttempts) {
      console.error('Max WebSocket reconnect attempts reached');
      return;
    }

    try {
      const ws = new WebSocket(url);

      ws.onopen = () => {
        setIsConnected(true);
        setReconnectAttempts(0);
        console.log('WebSocket connected');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onMessage) onMessage(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        setSocket(null);
        console.log('WebSocket disconnected. Attempting to reconnect...');
        
        // Auto reconnect
        setTimeout(() => {
          setReconnectAttempts((prev) => prev + 1);
          connect();
        }, reconnectInterval);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error', error);
        ws.close();
      };

      setSocket(ws);
    } catch (error) {
      console.error('Failed to establish WebSocket connection', error);
    }
  }, [url, onMessage, reconnectInterval, maxReconnectAttempts, reconnectAttempts]);

  useEffect(() => {
    connect();
    
    return () => {
      if (socket) {
        socket.close();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sendMessage = useCallback((message: any) => {
    if (socket && isConnected) {
      socket.send(JSON.stringify(message));
    } else {
      console.error('WebSocket is not connected');
    }
  }, [socket, isConnected]);

  return { isConnected, sendMessage };
}
