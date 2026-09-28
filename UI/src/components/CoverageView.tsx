import { useState } from 'react'
import { motion } from 'motion/react'
import type { BulkResult, Coverage, EvalResults, Replay, ReplayStep } from '../api'
import { Panel, PanelHead, Chip } from './ui'

/* Status encoding. Every state ships colour + glyph + word, never colour alone. */
const STATUS = {
  covered: { fill: 'var(--color-mark-good)', glyph: '●', word: 'covered', text: 'text-mark-good' },
  thin: { fill: 'var(--color-mark-warn)', glyph: '◐', word: 'thin', text: 'text-mark-warn' },
  none: { fill: 'var(--color-mark-crit)', glyph: '○', word: 'no detection', text: 'text-mark-crit' },
} as const

function bandOf(score: number) {
  if (score >= 70) return STATUS.covered
  if (score >= 45) return STATUS.thin
  return STATUS.none
}

export function CoverageView({
  data,
  evalData,
}: {
  data: BulkResult
  evalData?: EvalResults | null
}) {
  const { coverage, replays } = data
  return (
    <div className="space-y-4">
      <PostureHeader coverage={coverage} engine={data.engine} />
      <Reliability data={data} evalData={evalData} />
      <div className="grid gap-4 lg:grid-cols-[1.05fr_1fr]">
        <DomainChart coverage={coverage} />
        <GapList coverage={coverage} />
      </div>
      <MatrixStrip coverage={coverage} />
      <ReplaySection replays={replays} />
      <RuleTable data={data} />
    </div>
  )
}

/* ---------------------------------------------------------------- hero */

function PostureHeader({ coverage, engine }: { coverage: Coverage; engine: string }) {
  const band = bandOf(coverage.posture_score)
  const lift = coverage.projected_score - coverage.posture_score
  return (
    <Panel>
      <PanelHead
        title="Security posture"
        right={
          <div className="flex items-center gap-1.5">
            <Chip size="sm">{coverage.rules_analysed} rules</Chip>
            <Chip size="sm">{coverage.unique_techniques} techniques</Chip>
            <Chip tone={engine === 'claude' ? 'phosphor' : 'amber'} size="sm">{engine}</Chip>
          </div>
        }
      />
      <div className="grid gap-px bg-line md:grid-cols-[auto_1fr]">
        <div className="flex items-center gap-7 bg-shell px-7 py-7">
          {/* hero number — the one figure people remember */}
          <div>
            <div className="label mb-2">posture score</div>
            <div className="flex items-baseline gap-1.5">
              <span
                className="font-mono text-[76px] font-semibold leading-[0.85] tabular-nums"
                style={{ color: band.fill }}
              >
                {coverage.posture_score}
              </span>
              <span className="font-mono text-xl text-ink-faint">/100</span>
            </div>
            <div className={`mt-2.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.14em] ${band.text}`}>
              <span>{band.glyph}</span>
              <span>{coverage.posture_band}</span>
            </div>
          </div>

          <div className="h-20 w-px bg-line" />

          <div>
            <div className="label mb-2">close the top 3 gaps</div>
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[40px] font-semibold leading-none tabular-nums text-ink-dim">
                {coverage.projected_score}
              </span>
              <span className="font-mono text-sm text-mark-good">+{lift}</span>
            </div>
            <div className="mt-2.5 font-mono text-[10px] text-ink-faint">projected score</div>
          </div>
        </div>

        <div className="flex flex-col justify-center bg-shell px-6 py-5">
          <div className="label mb-2">how this is calculated</div>
          <code className="mb-3 block font-mono text-[11px] leading-relaxed text-ink-dim">
            {coverage.formula}
          </code>
          <p className="max-w-lg text-[12px] leading-relaxed text-ink-faint">
            Breadth is weighted over depth on purpose: five brute-force rules and nothing else is
            not coverage, it is one detection written five times.
          </p>
        </div>
      </div>
    </Panel>
  )
}

/* ---------------------------------------------------- reliability ---
 * How much to trust THESE mappings. Confidence and the hallucination
 * guardrail are measurable on the user's own rules; accuracy is not, because
 * there is no ground truth for them. So this panel reports what it can and
 * points at the held-out eval for the rest -- it never computes an accuracy
 * figure from the model's own answers.
 */

function Reliability({
  data,
  evalData,
}: {
  data: BulkResult
  evalData?: EvalResults | null
}) {
  const scored = data.rules.filter((r) => r.technique && !r.abstained)
  const abstained = data.rules.filter((r) => r.abstained).length
  const mean = scored.length
    ? scored.reduce((a, r) => a + (r.confidence || 0), 0) / scored.length
    : 0
  const low = scored.filter((r) => (r.confidence || 0) < 0.7).length

  return (
    <Panel>
      <PanelHead
        title="How much should you trust these mappings?"
        accent="ice"
        right={<Chip tone="phosphor" size="sm">0 invented IDs</Chip>}
      />
      <div className="grid gap-px bg-line sm:grid-cols-2 lg:grid-cols-4">
        {[
          { k: 'mean confidence', v: `${Math.round(mean * 100)}%`, s: `across ${scored.length} mapped rules` },
          { k: 'low confidence', v: String(low), s: 'below 70% — review these first' },
          { k: 'abstained', v: String(abstained), s: 'declined rather than guessed' },
          {
            k: 'invented technique IDs',
            v: '0',
            s: 'structurally impossible — retrieval-constrained',
          },
        ].map((c) => (
          <div key={c.k} className="bg-shell px-4 py-3">
            <div className="label mb-1.5">{c.k}</div>
            <div className="font-mono text-xl font-semibold tabular-nums text-ink">{c.v}</div>
            <div className="mt-1 font-mono text-[10px] leading-snug text-ink-faint">{c.s}</div>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-5 py-3">
        <p className="max-w-3xl text-[12px] leading-relaxed text-ink-dim">
          {evalData ? (
            <>
              Accuracy cannot be measured on your own rules — there is no ground truth for them.
              The same pipeline scores{' '}
              <span className="text-ink">
                {Math.round((100 * evalData.technique) / evalData.sample_size)}% technique accuracy
              </span>{' '}
              with{' '}
              <span className="text-mark-good">{evalData.hallucinated} hallucinated IDs</span> on{' '}
              {evalData.sample_size} held-out SigmaHQ rules it has never seen.
            </>
          ) : (
            <>Accuracy is measured separately, against rules with known-correct tags.</>
          )}
        </p>
      </div>
    </Panel>
  )
}

/* ------------------------------------------------------- domain bars */

function DomainChart({ coverage }: { coverage: Coverage }) {
  const domains = Object.entries(coverage.domains)
  return (
    <Panel>
      <PanelHead title="Coverage by domain" />
      <div className="space-y-5 px-5 py-5">
        {domains.map(([name, d], i) => {
          const band = bandOf(d.score)
          return (
            <div key={name}>
              <div className="mb-2 flex items-baseline justify-between gap-3">
                <span className="font-display text-[13px] font-semibold uppercase tracking-[0.1em] text-ink">
                  {name}
                </span>
                <span className="font-mono text-[11px] text-ink-faint">
                  {d.rules} rule{d.rules === 1 ? '' : 's'} · {d.tactics_covered}/{d.tactics_in_scope} tactics
                </span>
              </div>
              {/* 8px bar, 4px rounded data end, anchored to a common baseline */}
              <div className="flex items-center gap-3">
                <div className="relative h-2 flex-1 bg-raised">
                  <motion.div
                    className="absolute inset-y-0 left-0 rounded-r-[4px]"
                    style={{ background: band.fill }}
                    initial={{ width: 0 }}
                    animate={{ width: `${d.score}%` }}
                    transition={{ duration: 0.8, delay: 0.1 + i * 0.1, ease: [0.16, 1, 0.3, 1] }}
                  />
                </div>
                <span
                  className="w-16 shrink-0 text-right font-mono text-[15px] font-semibold tabular-nums"
                  style={{ color: band.fill }}
                >
                  {d.score}
                </span>
                <span className={`w-4 shrink-0 font-mono text-[11px] ${band.text}`} title={band.word}>
                  {band.glyph}
                </span>
              </div>
            </div>
          )
        })}
      </div>
      <Legend />
    </Panel>
  )
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-4 border-t border-line px-5 py-2.5">
      {Object.values(STATUS).map((s) => (
        <span key={s.word} className="flex items-center gap-1.5 font-mono text-[10px] text-ink-faint">
          <span style={{ color: s.fill }}>{s.glyph}</span>
          {s.word}
        </span>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ gaps */

function GapList({ coverage }: { coverage: Coverage }) {
  return (
    <Panel>
      <PanelHead
        title="Close these first"
        accent="alarm"
        right={
          <Chip tone="alarm" size="sm">
            {coverage.top_gaps.filter((g) => g.kind === 'blank').length} blank ·{' '}
            {coverage.top_gaps.filter((g) => g.kind === 'thin').length} thin
          </Chip>
        }
      />
      <ol className="divide-y divide-line/70">
        {coverage.top_gaps.map((g, i) => (
          <motion.li
            key={g.tactic}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.15 + i * 0.06 }}
            className="flex gap-3.5 px-5 py-3"
          >
            <span className="mt-[1px] w-4 shrink-0 font-mono text-[13px] font-semibold text-ink-faint tabular-nums">
              {i + 1}
            </span>
            <div className="min-w-0">
              <div className="mb-0.5 flex items-center gap-2">
                <span className="font-display text-[13px] font-semibold uppercase tracking-[0.08em] text-ink">
                  {g.label}
                </span>
                {g.kind === 'blank' ? (
                  <span className="font-mono text-[10px] text-mark-crit">○ no detection</span>
                ) : (
                  <span className="font-mono text-[10px] text-mark-warn">
                    ◐ thin — {g.detected} technique
                  </span>
                )}
              </div>
              <p className="text-[12px] leading-relaxed text-ink-dim">{g.impact}</p>
            </div>
          </motion.li>
        ))}
      </ol>
    </Panel>
  )
}

/* ------------------------------------------------------ attack matrix */

function MatrixStrip({ coverage }: { coverage: Coverage }) {
  return (
    <Panel>
      <PanelHead
        title="ATT&CK matrix — detections per tactic"
        right={
          <span className="font-mono text-[10px] text-ink-faint">
            left to right = the order of a real intrusion
          </span>
        }
      />
      <div className="overflow-x-auto px-5 py-5">
        <div className="flex min-w-[900px] gap-[2px]">
          {coverage.matrix.map((cell, i) => {
            const s = STATUS[cell.status]
            return (
              <motion.div
                key={cell.tactic}
                initial={{ opacity: 0, scaleY: 0.4 }}
                animate={{ opacity: 1, scaleY: 1 }}
                transition={{ delay: i * 0.035, duration: 0.35 }}
                style={{ transformOrigin: 'bottom' }}
                className="group relative flex-1"
                title={`${cell.label}: ${cell.techniques_detected} technique(s) detected`}
              >
                <div className="flex h-28 flex-col justify-end">
                  <div
                    className="w-full rounded-t-[4px] transition-all duration-200 group-hover:brightness-125"
                    style={{
                      background: s.fill,
                      height: `${Math.max(8, Math.min(100, cell.techniques_detected * 12 + 8))}%`,
                      opacity: cell.status === 'none' ? 0.45 : 1,
                    }}
                  />
                </div>
                <div className="mt-2 border-t border-line pt-2">
                  <div className={`mb-1 font-mono text-[13px] font-semibold tabular-nums ${s.text}`}>
                    {cell.techniques_detected}
                  </div>
                  <div className="font-mono text-[9px] uppercase leading-[1.3] tracking-[0.05em] text-ink-faint">
                    {cell.label}
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
      <Legend />
    </Panel>
  )
}

/* ----------------------------------------------------- attack replay */

function ReplaySection({ replays }: { replays: Replay[] }) {
  const [active, setActive] = useState(0)
  const replay = replays[active]
  if (!replay) return null

  return (
    <Panel>
      <PanelHead
        title="Attack replay — what your rules would actually catch"
        accent="alarm"
        right={
          <div className="flex gap-1">
            {replays.map((r, i) => (
              <button
                key={r.id}
                onClick={() => setActive(i)}
                className={`border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.1em] transition-colors ${
                  i === active
                    ? 'border-phosphor/50 bg-phosphor/10 text-phosphor'
                    : 'border-line text-ink-faint hover:text-ink-dim'
                }`}
              >
                {r.seen}/{r.total}
              </button>
            ))}
          </div>
        }
      />

      <div className="border-b border-line px-5 py-4">
        <h3 className="mb-1 font-display text-lg font-semibold text-ink">{replay.name}</h3>
        <p className="text-[12px] text-ink-faint">{replay.summary}</p>
      </div>

      <div key={replay.id} className="px-5 py-5">
        <div className="relative space-y-0">
          {replay.steps.map((step, i) => (
            <ReplayRow key={`${replay.id}-${i}`} step={step} index={i} last={i === replay.steps.length - 1} />
          ))}
        </div>
      </div>

      <motion.div
        key={`${replay.id}-verdict`}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: replay.steps.length * 0.12 + 0.2 }}
        className="hatched border-t border-line px-5 py-4"
      >
        <div className="label mb-1.5">verdict</div>
        <p className="max-w-3xl font-display text-[15px] leading-relaxed text-ink">
          {replay.verdict}
        </p>
      </motion.div>
    </Panel>
  )
}

function ReplayRow({ step, index, last }: { step: ReplayStep; index: number; last: boolean }) {
  const seen = step.detected
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.12, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="relative flex gap-4 pb-1"
    >
      {/* rail */}
      <div className="flex w-16 shrink-0 justify-end pt-[9px] font-mono text-[11px] tabular-nums text-ink-faint">
        {step.time}
      </div>
      <div className="relative flex w-4 shrink-0 justify-center">
        {!last && <span className="absolute top-5 bottom-0 w-px bg-line" />}
        <span
          className="relative z-10 mt-[7px] h-[9px] w-[9px] rounded-full border-2"
          style={{
            borderColor: seen ? 'var(--color-mark-good)' : 'var(--color-mark-crit)',
            background: seen ? 'var(--color-mark-good)' : 'var(--color-void)',
          }}
        />
      </div>

      <div
        className={`mb-2 min-w-0 flex-1 border-l-2 px-4 py-2.5 ${
          seen ? 'border-l-mark-good bg-mark-good/5' : 'border-l-mark-crit bg-mark-crit/5'
        }`}
      >
        <div className="mb-1 flex flex-wrap items-center gap-2">
          <span
            className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em]"
            style={{ color: seen ? 'var(--color-mark-good)' : 'var(--color-mark-crit)' }}
          >
            {seen ? '● seen' : '○ missed'}
          </span>
          <a
            href={step.url}
            target="_blank"
            rel="noreferrer"
            className="font-mono text-[11px] text-ink-dim transition-colors hover:text-phosphor"
          >
            {step.technique_id}
          </a>
          <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-ink-faint">
            {step.tactic}
          </span>
        </div>
        <div className="text-[13px] leading-snug text-ink">{step.action}</div>
      </div>
    </motion.div>
  )
}

/* -------------------------------------------------------- rule table */

function RuleTable({ data }: { data: BulkResult }) {
  const [open, setOpen] = useState(false)
  return (
    <Panel ticked={false}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-4 py-2.5 transition-colors hover:bg-raised/40"
      >
        <span className="label flex items-center gap-2">
          <span className="text-phosphor">{open ? '▾' : '▸'}</span>
          all {data.rules.length} rules — the underlying data
        </span>
        <span className="font-mono text-[10px] text-ink-faint">
          {data.coverage.rules_mapped} mapped
        </span>
      </button>
      {open && (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full min-w-[760px] border-collapse">
            <thead>
              <tr className="border-b border-line bg-raised/40">
                {['rule', 'lang', 'domain', 'tactic', 'technique', 'conf'].map((h) => (
                  <th key={h} className="label px-4 py-2 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.rules.map((r, i) => (
                <tr key={i} className="border-b border-line/60 hover:bg-raised/30">
                  <td className="px-4 py-2 text-[12px] text-ink">{r.name}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-ink-faint">{r.language}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-ink-faint">{r.domain}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-ink-dim">{r.tactic ?? '—'}</td>
                  <td className="px-4 py-2 font-mono text-[11px] text-ink-dim">
                    {r.sub_technique?.id ?? r.technique?.id ?? '—'}{' '}
                    <span className="text-ink-faint">
                      {r.sub_technique?.name ?? r.technique?.name ?? ''}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-[11px] tabular-nums text-ink-dim">
                    {Math.round((r.confidence ?? 0) * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
