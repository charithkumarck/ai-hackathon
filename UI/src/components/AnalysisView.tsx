import { useState } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import { api, type Analysis, type GapSuggestion, type Generated } from '../api'
import { Panel, PanelHead, Chip, ConfidenceMeter, Button, Code } from './ui'

const rise = (i: number) => ({
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.45, delay: i * 0.07, ease: [0.16, 1, 0.3, 1] as const },
})

export function AnalysisView({ result }: { result: Analysis }) {
  const { mapping, critique, parsed, gaps, trace, security } = result
  const tech = mapping.technique
  const sub = mapping.sub_technique

  return (
    <div className="space-y-4">
      {security.blocked && <InjectionBanner findings={security.injection_attempts} />}

      {/* ---------------- the mapping ---------------- */}
      <motion.div {...rise(0)}>
        <Panel>
          <PanelHead
            title="ATT&CK mapping"
            right={
              <div className="flex items-center gap-1.5">
                <Chip tone="ice" size="sm">{parsed.language}</Chip>
                <Chip size="sm">{parsed.domain}</Chip>
                {/* Any real provider is green; only the heuristic is amber. */}
                <Chip
                  tone={result.engine === 'offline-heuristic' ? 'amber' : 'phosphor'}
                  size="sm"
                >
                  {result.engine === 'offline-heuristic' ? 'offline' : result.engine}
                </Chip>
              </div>
            }
          />

          {mapping.abstain || !tech ? (
            <div className="px-5 py-8">
              <div className="mb-2 font-display text-2xl font-semibold text-amber">
                Uncertain — not guessing
              </div>
              <p className="max-w-xl text-sm leading-relaxed text-ink-dim">
                {mapping.ambiguity_note ||
                  'No candidate technique was a defensible match for this query.'}
              </p>
            </div>
          ) : (
            <div className="px-5 py-6">
              <div className="mb-1 flex flex-wrap items-baseline gap-x-2.5 gap-y-1 font-mono text-[11px] uppercase tracking-[0.15em] text-ink-faint">
                <span className="text-phosphor">{mapping.tactic}</span>
                <span className="text-line-bright">/</span>
                <span>{tech.name}</span>
                {sub && (
                  <>
                    <span className="text-line-bright">/</span>
                    <span>{sub.name}</span>
                  </>
                )}
              </div>

              <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
                <a
                  href={(sub ?? tech).url}
                  target="_blank"
                  rel="noreferrer"
                  className="group font-mono text-[56px] font-semibold leading-[0.95] tracking-tight text-ink transition-colors hover:text-phosphor"
                >
                  {(sub ?? tech).id}
                  <span className="ml-3 align-super font-mono text-[11px] font-normal text-ink-faint opacity-0 transition-opacity group-hover:opacity-100">
                    attack.mitre.org ↗
                  </span>
                </a>
                <div className="pb-2">
                  <div className="label mb-2">mapping confidence</div>
                  <ConfidenceMeter value={mapping.confidence} />
                </div>
              </div>

              <div className="mt-5 max-w-3xl border-l-2 border-line pl-4">
                <div className="label mb-1.5">why</div>
                <p className="text-[13px] leading-relaxed text-ink-dim">{mapping.reasoning}</p>
              </div>

              {mapping.rejected.length > 0 && (
                <div className="mt-4 max-w-3xl">
                  <div className="label mb-2">ruled out</div>
                  <div className="space-y-1.5">
                    {mapping.rejected.map((r) => (
                      <div key={r.id} className="flex gap-3 font-mono text-[11px]">
                        <span className="shrink-0 text-ink-faint line-through">{r.id}</span>
                        <span className="text-ink-faint">{r.why}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <ObservesStrip result={result} />
        </Panel>
      </motion.div>

      {/* ---------------- blind spots ---------------- */}
      <motion.div {...rise(1)}>
        <Panel className="hatched">
          <PanelHead
            title="What this rule cannot see"
            accent="alarm"
            right={<Chip tone="alarm" size="sm">{critique.blind_spots.length} blind spots</Chip>}
          />
          <ul className="divide-y divide-line/70">
            {critique.blind_spots.map((b, i) => (
              <li key={i} className="flex gap-3 px-5 py-3">
                <span className="mt-[3px] shrink-0 font-mono text-[11px] text-alarm">▸</span>
                <span className="text-[13px] leading-relaxed text-ink-dim">{b}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </motion.div>

      {/* ---------------- telemetry upgrades ---------------- */}
      <motion.div {...rise(2)}>
        <Panel>
          <PanelHead title="Make it stronger" accent="amber" />
          <ul className="divide-y divide-line/70">
            {critique.telemetry_upgrades.map((t, i) => (
              <li key={i} className="flex gap-3 px-5 py-3">
                <span className="mt-[2px] shrink-0 font-mono text-[12px] text-amber">+</span>
                <span className="text-[13px] leading-relaxed text-ink-dim">{t}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </motion.div>

      {/* ---------------- the gap chain ---------------- */}
      {gaps && gaps.suggestions.length > 0 && (
        <motion.div {...rise(3)}>
          <GapChain gaps={gaps} ruleText={parsed.language} />
        </motion.div>
      )}

      {/* ---------------- reasoning trace ---------------- */}
      <motion.div {...rise(4)}>
        <Trace trace={trace} result={result} />
      </motion.div>
    </div>
  )
}

function ObservesStrip({ result }: { result: Analysis }) {
  const { parsed, mapping } = result
  const cells = [
    { k: 'observes', v: mapping.what_it_observes },
    { k: 'telemetry', v: parsed.data_source },
    {
      k: 'time window',
      v: parsed.time_window ?? 'none declared',
      warn: !parsed.time_window,
    },
    {
      k: 'outcome visibility',
      v: parsed.observes_success
        ? parsed.observes_failure
          ? 'success + failure'
          : 'success only'
        : parsed.observes_failure
          ? 'failures only'
          : 'unspecified',
      warn: parsed.observes_failure && !parsed.observes_success,
    },
  ]
  return (
    <div className="grid grid-cols-1 gap-px border-t border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
      {cells.map((c) => (
        <div key={c.k} className="bg-shell px-4 py-3">
          <div className="label mb-1.5">{c.k}</div>
          <div
            className={`font-mono text-[11px] leading-relaxed ${c.warn ? 'text-alarm' : 'text-ink-dim'}`}
          >
            {c.v}
          </div>
        </div>
      ))}
    </div>
  )
}

function InjectionBanner({ findings }: { findings: { location: string; detail: string }[] }) {
  return (
    <motion.div initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }}>
      <div className="border border-phosphor/40 bg-phosphor/8 px-5 py-4">
        <div className="mb-2 flex items-center gap-2.5">
          <span className="font-mono text-base text-phosphor">⬢</span>
          <span className="font-display text-sm font-semibold uppercase tracking-[0.12em] text-phosphor">
            Prompt injection neutralised
          </span>
        </div>
        <p className="mb-3 max-w-2xl text-[12px] leading-relaxed text-ink-dim">
          This rule contained text aimed at the model rather than the SIEM. It was stripped during
          parsing and never reached the prompt — only the query logic was analysed.
        </p>
        {findings.map((f, i) => (
          <div key={i} className="mb-1 font-mono text-[11px]">
            <span className="text-ink-faint">{f.location}: </span>
            <span className="text-alarm line-through">{f.detail}</span>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

function GapChain({
  gaps,
  ruleText,
}: {
  gaps: NonNullable<Analysis['gaps']>
  ruleText: string
}) {
  return (
    <Panel>
      <PanelHead
        title="You're missing the rest of the chain"
        accent="ice"
        right={<Chip tone="ice" size="sm">{gaps.suggestions.length} gaps</Chip>}
      />
      <p className="border-b border-line px-5 py-3.5 text-[13px] leading-relaxed text-ink-dim">
        {gaps.narrative}
      </p>

      <div className="px-5 py-4">
        <div className="mb-4 flex items-center gap-3">
          <span className="flex h-6 items-center border border-phosphor/40 bg-phosphor/10 px-2 font-mono text-[10px] font-medium text-phosphor">
            ✓ {gaps.you_detect.id}
          </span>
          <span className="font-mono text-[11px] text-ink-faint">
            {gaps.you_detect.name} — the only stage you cover
          </span>
        </div>

        <div className="relative space-y-3 pl-5">
          <span className="absolute left-[3px] top-1 bottom-4 w-px bg-gradient-to-b from-phosphor/50 via-alarm/40 to-transparent" />
          {gaps.suggestions.map((g, i) => (
            <GapRow key={g.id} gap={g} index={i} language={ruleText} />
          ))}
        </div>
      </div>
    </Panel>
  )
}

const PRIORITY_TONE = {
  critical: 'alarm',
  high: 'amber',
  medium: 'neutral',
} as const

function GapRow({
  gap,
  index,
  language,
}: {
  gap: GapSuggestion
  index: number
  language: string
}) {
  const [generated, setGenerated] = useState<Generated | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const lang = ['SPL', 'KQL', 'YARA-L'].includes(language) ? language : 'SPL'

  async function run() {
    setBusy(true)
    setError('')
    try {
      setGenerated(await api.generate(gap.id, lang, ''))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.1 + index * 0.08, duration: 0.4 }}
      className="relative"
    >
      <span className="absolute -left-[22px] top-3 h-[7px] w-[7px] border border-alarm bg-void" />
      <div className="border border-line bg-shell/70">
        <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <a
                href={gap.url}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-[13px] font-semibold text-ink transition-colors hover:text-phosphor"
              >
                {gap.id}
              </a>
              <Chip tone={PRIORITY_TONE[gap.priority]} size="sm">
                {gap.priority}
              </Chip>
              <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-faint">
                {gap.tactic}
              </span>
            </div>
            <div className="mb-1 text-[13px] font-medium text-ink">{gap.title}</div>
            <p className="max-w-2xl text-[12px] leading-relaxed text-ink-faint">{gap.why}</p>
          </div>
          <Button size="sm" onClick={run} disabled={busy}>
            {busy ? 'writing…' : generated ? 'regenerate' : `write ${lang} ▸`}
          </Button>
        </div>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              className="border-t border-alarm/30 bg-alarm/5 px-4 py-2 font-mono text-[11px] text-alarm"
            >
              {error}
            </motion.div>
          )}
          {generated && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              className="overflow-hidden border-t border-phosphor/25"
            >
              <div className="flex items-center justify-between border-b border-line bg-raised/50 px-4 py-2">
                <span className="label">generated {generated.language} — paste into your SIEM</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(generated.query)}
                >
                  copy
                </Button>
              </div>
              <Code>{generated.query}</Code>
              <div className="border-t border-line px-4 py-3">
                <p className="mb-2 text-[12px] leading-relaxed text-ink-dim">
                  {generated.explanation}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {generated.required_telemetry.map((t) => (
                    <Chip key={t} size="sm">{t}</Chip>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}

function Trace({ trace, result }: { trace: string[]; result: Analysis }) {
  const [open, setOpen] = useState(false)
  return (
    <Panel ticked={false}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-raised/40"
      >
        <span className="label flex items-center gap-2">
          <span className="text-phosphor">{open ? '▾' : '▸'}</span>
          how we got here — {trace.length} steps
        </span>
        <span className="font-mono text-[10px] text-ink-faint">
          {result.retrieval.pool_size} candidate pool · {result.timing_ms}ms
        </span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-line"
          >
            <ol className="bg-void/60 px-4 py-3 font-mono text-[11px] leading-[1.9] text-ink-dim">
              {trace.map((t, i) => (
                <li key={i} className="flex gap-3">
                  <span className="shrink-0 text-ink-faint">{String(i + 1).padStart(2, '0')}</span>
                  <span>{t}</span>
                </li>
              ))}
            </ol>
            <div className="border-t border-line px-4 py-3">
              <div className="label mb-2">retrieved candidates — the model could pick nothing else</div>
              <div className="flex flex-wrap gap-1.5">
                {result.retrieval.candidates.map((c) => {
                  const chosen =
                    c.id === result.mapping.technique?.id || c.id === result.mapping.sub_technique?.id
                  return (
                    <span
                      key={c.id}
                      className={`border px-2 py-0.5 font-mono text-[10px] ${
                        chosen
                          ? 'border-phosphor/50 bg-phosphor/10 text-phosphor'
                          : 'border-line text-ink-faint'
                      }`}
                      title={c.name}
                    >
                      {c.id} · {c.score}
                    </span>
                  )
                })}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Panel>
  )
}
