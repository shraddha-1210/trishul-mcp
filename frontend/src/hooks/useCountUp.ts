import { useEffect, useRef, useState } from "react"

/** Animate 0 -> value over `duration` ms on mount and whenever the value changes. */
export function useCountUp(value: number, duration = 400): number {
  const [shown, setShown] = useState(value)
  const from = useRef(0)

  useEffect(() => {
    const start = performance.now()
    const origin = from.current
    let frame = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      // ease-out cubic
      const eased = 1 - (1 - t) ** 3
      setShown(origin + (value - origin) * eased)
      if (t < 1) frame = requestAnimationFrame(tick)
      else from.current = value
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, duration])

  return shown
}
