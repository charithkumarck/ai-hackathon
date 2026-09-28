import type { ReactNode } from 'react'

export function Panel({
  children,
  className = '',
  ticked = true,
  scanning = false,
}: {
  children: ReactNode
  className?: string
  ticked?: boolean
  scanning?: boolean
}) {
  return (
    <div
      className={`panel ${ticked ? 'ticked' : ''} ${scanning ? 'scanning' : ''} overflow-hidden ${className}`}
    >
      {children}
    </div>
  )
}

export function PanelHead({
  title,
  right,
  accent = 'phosphor',
}: {
  title: string
  right?: ReactNode
  accent?: 'phosphor' | 'alarm' | 'amber' | 'ice'
}) {
  const bar = {
    phosphor: 'bg-phosphor',
    alarm: 'bg-alarm',
    amber: 'bg-amber',
    ice: 'bg-ice',
  }[accent]
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
      <div className="flex items-center gap-2.5 min-w-0">
        <span className={`h-3 w-[2px] shrink-0 ${bar}`} />
        <span className="label truncate">{title}</span>
      </div>
      {right}
    </div>
  )
}

export function Chip({
  children,
  tone = 'neutral',
  size = 'md',
}: {
  children: ReactNode
  tone?: 'neutral' | 'phosphor' | 'alarm' | 'amber' | 'ice'
  size?: 'sm' | 'md'
}) {
  const tones = {
    neutral: 'border-line text-ink-dim bg-raised/60',
    phosphor: 'border-phosphor/35 text-phosphor bg-phosphor/8',
    alarm: 'border-alarm/40 text-alarm bg-alarm/8',
    amber: 'border-amber/40 text-amber bg-amber/8',
    ice: 'border-ice/35 text-ice bg-ice/8',
  }[tone]
  const dims = size === 'sm' ? 'px-1.5 py-[1px] text-[9px]' : 'px-2 py-0.5 text-[10px]'
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap border font-mono font-medium uppercase tracking-[0.12em] ${dims} ${tones}`}
    >
      {children}
    </span>
  )
}

/** Segmented confidence readout — instrument, not progress bar. */
export function ConfidenceMeter({ value, segments = 24 }: { value: number; segments?: number }) {
  const filled = Math.round(value * segments)
  const tone = value >= 0.85 ? 'phosphor' : value >= 0.6 ? 'amber' : 'alarm'
  const color = {
    phosphor: 'bg-phosphor shadow-[0_0_6px_rgba(77,240,196,0.65)]',
    amber: 'bg-amber shadow-[0_0_6px_rgba(255,179,64,0.6)]',
    alarm: 'bg-alarm shadow-[0_0_6px_rgba(255,77,94,0.6)]',
  }[tone]
  const text = { phosphor: 'text-phosphor', amber: 'text-amber', alarm: 'text-alarm' }[tone]
  return (
    <div className="flex items-center gap-3">
      <div className="flex gap-[3px]">
        {Array.from({ length: segments }, (_, i) => (
          <span
            key={i}
            className={`h-4 w-[5px] transition-all duration-500 ${i < filled ? color : 'bg-line'}`}
            style={{ transitionDelay: `${i * 18}ms` }}
          />
        ))}
      </div>
      <span className={`font-mono text-lg font-semibold tabular-nums ${text}`}>
        {Math.round(value * 100)}%
      </span>
    </div>
  )
}

export function Stat({
  label,
  value,
  sub,
  tone = 'ink',
}: {
  label: string
  value: ReactNode
  sub?: string
  tone?: 'ink' | 'phosphor' | 'alarm' | 'amber'
}) {
  const color = {
    ink: 'text-ink',
    phosphor: 'text-phosphor',
    alarm: 'text-alarm',
    amber: 'text-amber',
  }[tone]
  return (
    <div className="px-4 py-3">
      <div className="label mb-1.5">{label}</div>
      <div className={`font-mono text-2xl font-semibold tabular-nums leading-none ${color}`}>
        {value}
      </div>
      {sub && <div className="mt-1.5 font-mono text-[10px] text-ink-faint">{sub}</div>}
    </div>
  )
}

export function Button({
  children,
  onClick,
  disabled,
  variant = 'primary',
  size = 'md',
}: {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  variant?: 'primary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
}) {
  const variants = {
    primary:
      'border-phosphor/50 bg-phosphor/10 text-phosphor hover:bg-phosphor/20 hover:border-phosphor disabled:opacity-35',
    ghost: 'border-line bg-transparent text-ink-dim hover:text-ink hover:border-line-bright',
    danger: 'border-alarm/45 bg-alarm/10 text-alarm hover:bg-alarm/20 hover:border-alarm',
  }[variant]
  const dims = size === 'sm' ? 'px-2.5 py-1 text-[10px]' : 'px-4 py-2 text-[11px]'
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`border font-mono font-medium uppercase tracking-[0.14em] transition-all duration-150 disabled:cursor-not-allowed active:translate-y-px ${dims} ${variants}`}
    >
      {children}
    </button>
  )
}

export function Code({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto whitespace-pre-wrap break-words bg-void/70 px-4 py-3 font-mono text-[12px] leading-[1.7] text-ink-dim">
      {children}
    </pre>
  )
}
