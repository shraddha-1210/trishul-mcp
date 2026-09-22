// Backend base URL. Override with VITE_API_URL in frontend/.env.local, e.g. when
// port 8002 is the demo port (8000 is taken by Docker on this machine).
export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8002"
export const WS_URL: string = API_URL.replace(/^http/, "ws") + "/ws/live"
