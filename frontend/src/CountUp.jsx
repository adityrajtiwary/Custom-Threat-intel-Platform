import { useState, useEffect, useRef } from 'react'

export default function CountUp({ end, duration = 1200 }) {
  const [val, setVal] = useState(0)
  const ref = useRef()

  useEffect(() => {
    let start = null
    const from = 0
    function step(ts) {
      if (!start) start = ts
      const progress = Math.min((ts - start) / duration, 1)
      // easeOutExpo -- fast start, smooth end
      const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress)
      setVal(Math.floor(from + (end - from) * eased))
      if (progress < 1) ref.current = requestAnimationFrame(step)
    }
    ref.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(ref.current)
  }, [end, duration])

  return <>{val.toLocaleString()}</>
}
