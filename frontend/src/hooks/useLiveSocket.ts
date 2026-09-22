import { useEffect, useRef } from "react"

import { WS_URL } from "@/lib/api"
import { useVerdictsStore } from "@/stores/verdicts"

/**
 * Subscribe to /ws/live for the lifetime of the page. Pipeline events land in the
 * verdicts store as they arrive; the backend never expects anything from us.
 * A dropped socket retries every 2 s so a backend restart heals without a reload.
 */
export function useLiveSocket() {
  const applyEvent = useVerdictsStore((s) => s.applyEvent)
  const setConnected = useVerdictsStore((s) => s.setConnected)
  const retry = useRef<number | undefined>(undefined)

  useEffect(() => {
    let socket: WebSocket | null = null
    let closed = false

    const connect = () => {
      socket = new WebSocket(WS_URL)
      socket.onopen = () => setConnected(true)
      socket.onmessage = (e) => {
        try {
          applyEvent(JSON.parse(e.data))
        } catch {
          // Ignore a frame we cannot parse; the POST response is the source of truth.
        }
      }
      socket.onclose = () => {
        setConnected(false)
        if (!closed) retry.current = window.setTimeout(connect, 2000)
      }
      socket.onerror = () => socket?.close()
    }
    connect()

    return () => {
      closed = true
      window.clearTimeout(retry.current)
      if (!socket) return
      // Detach the handlers first: this socket is being discarded, and its late
      // onclose must not flip the connection state a newer socket just set.
      const discarded = socket
      discarded.onmessage = null
      discarded.onclose = null
      discarded.onerror = null
      // Closing mid-handshake logs a browser warning (StrictMode mounts twice),
      // so wait for the socket to open before closing it.
      if (discarded.readyState === WebSocket.CONNECTING) {
        discarded.onopen = () => discarded.close()
      } else {
        discarded.onopen = null
        discarded.close()
      }
    }
  }, [applyEvent, setConnected])
}
