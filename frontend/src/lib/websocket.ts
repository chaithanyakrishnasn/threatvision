'use client'

import { useEffect, useRef, useCallback } from 'react'
import type { WsMessage, WsEventType } from '@/types'

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000'

type MessageHandler = (data: unknown) => void

class WebSocketClient {
  private ws: WebSocket | null = null
  private handlers: Map<WsEventType | '*', Set<MessageHandler>> = new Map()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 2000
  private maxDelay = 30000
  private url: string
  private connected = false

  constructor(url: string) {
    this.url = url
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return
    try {
      this.ws = new WebSocket(`${this.url}/ws`)

      this.ws.onopen = () => {
        this.connected = true
        this.reconnectDelay = 2000
        console.log('[WS] Connected to ThreatVision stream')
      }

      this.ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data)
          // Dispatch to type-specific handlers
          this.handlers.get(msg.type)?.forEach((h) => h(msg.data))
          // Dispatch to wildcard handlers
          this.handlers.get('*')?.forEach((h) => h(msg))
        } catch {
          // ignore malformed messages
        }
      }

      this.ws.onclose = () => {
        this.connected = false
        this._scheduleReconnect()
      }

      this.ws.onerror = () => {
        this.ws?.close()
      }
    } catch {
      this._scheduleReconnect()
    }
  }

  private _scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, this.maxDelay)
      this.connect()
    }, this.reconnectDelay)
  }

  on(event: WsEventType | '*', handler: MessageHandler) {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set())
    }
    this.handlers.get(event)!.add(handler)
    return () => this.off(event, handler)
  }

  off(event: WsEventType | '*', handler: MessageHandler) {
    this.handlers.get(event)?.delete(handler)
  }

  send(data: unknown) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
    }
    this.ws?.close()
    this.connected = false
  }

  get isConnected() {
    return this.connected
  }
}

// Singleton
let _client: WebSocketClient | null = null

export function getWsClient(): WebSocketClient {
  if (!_client) {
    _client = new WebSocketClient(WS_URL)
  }
  return _client
}

// ── React hook ────────────────────────────────────────────────────────────────
export function useWebSocket(
  event: WsEventType | '*',
  handler: MessageHandler,
  deps: unknown[] = []
) {
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  const stableHandler = useCallback(
    (data: unknown) => handlerRef.current(data),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps
  )

  useEffect(() => {
    const client = getWsClient()
    client.connect()
    const unsubscribe = client.on(event, stableHandler)
    return unsubscribe
  }, [event, stableHandler])
}
