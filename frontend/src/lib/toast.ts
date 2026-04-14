export type ToastType = 'success' | 'error' | 'info' | 'warning'

export interface Toast {
  id: string
  message: string
  type: ToastType
}

type ToastHandler = (toast: Toast) => void

let _handler: ToastHandler | null = null

export function registerToastHandler(h: ToastHandler) {
  _handler = h
}

export function showToast(message: string, type: ToastType = 'info') {
  const toast: Toast = { id: `${Date.now()}-${Math.random()}`, message, type }
  _handler?.(toast)
}
