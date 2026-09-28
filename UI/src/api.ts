export interface TechniqueBrief {
  id: string
  name: string
  tactic: string
  tactics: string[]
  is_sub: boolean
  parent_id: string | null
  url: string
  domains: string[]
}

export interface ParsedRule {
  language: string
  language_confidence: string
  data_source: string
  domain: string
  aggregation: string | null
  group_by: string[]
  threshold: { field: string; op: string; value: number } | null
  time_window: string | null
  observes_success: boolean
  observes_failure: boolean
  fields: string[]
  security_findings: { type: string; location: string; detail: string }[]
}

export interface Candidate {
  id: string
  name: string
  tactic: string
  score: number
  description: string
}

export interface GapSuggestion {
  id: string
  name: string
  tactic: string
  title: string
  why: string
  priority: 'critical' | 'high' | 'medium'
  url: string
}

export interface Analysis {
  ok: boolean
  engine: string
  timing_ms: number
  parsed: ParsedRule
  security: { injection_attempts: { location: string; detail: string }[]; blocked: boolean }
  mapping: {
    abstain: boolean
    tactic: string | null
    technique: TechniqueBrief | null
    sub_technique: TechniqueBrief | null
    confidence: number
    behaviour: string
    what_it_observes: string
    reasoning: string
    rejected: { id: string; name: string; why: string }[]
    ambiguity_note: string
  }
  critique: { blind_spots: string[]; telemetry_upgrades: string[] }
  retrieval: { candidates: Candidate[]; pool_size: number }
  trace: string[]
  gaps?: {
    narrative: string
    you_detect: { id: string; name: string; tactic: string }
    suggestions: GapSuggestion[]
  }
}

export interface DomainScore {
  score: number
  breadth_pct: number
  depth_pct: number
  tactics_covered: number
  tactics_in_scope: number
  rules: number
}

export interface Coverage {
  rules_analysed: number
  rules_mapped: number
  unique_techniques: number
  posture_score: number
  posture_band: string
  projected_score: number
  domains: Record<string, DomainScore>
  matrix: {
    tactic: string
    label: string
    techniques_detected: number
    technique_ids: string[]
    risk: number
    status: 'none' | 'thin' | 'covered'
  }[]
  top_gaps: {
    tactic: string
    label: string
    risk: number
    kind: 'blank' | 'thin'
    detected: number
    blind_domains: string[]
    impact: string
  }[]
  formula: string
}

export interface ReplayStep {
  time: string
  technique_id: string
  technique: string
  tactic: string
  action: string
  detected: boolean
  url: string
}

export interface Replay {
  id: string
  name: string
  summary: string
  steps: ReplayStep[]
  seen: number
  missed: number
  total: number
  verdict: string
}

export interface BulkResult {
  session_id: string
  engine: string
  rules: {
    name: string
    query: string
    language: string
    domain: string
    technique: TechniqueBrief | null
    sub_technique: TechniqueBrief | null
    tactic: string | null
    confidence: number
    abstained: boolean
  }[]
  coverage: Coverage
  replays: Replay[]
}

export interface Health {
  status: string
  attack: { techniques: number; sub_techniques: number; total: number; tactics: number }
  retrieval: { indexed_techniques: number; vocabulary: number }
  llm: { available: boolean; provider: string | null; model: string | null; reason: string | null }
  guardrail: { hallucinated_ids_blocked: number; policy: string }
}

export interface SeedRule {
  name: string
  language: string
  query: string
}

export interface EvalRow {
  title: string
  truth: string[]
  predicted: string
  predicted_tactic: string
  confidence: number
  abstained: boolean
  exact: boolean
  technique_ok: boolean
  tactic_ok: boolean
}

export interface EvalResults {
  provider: string
  model: string
  sample_size: number
  exact: number
  technique: number
  tactic: number
  abstained: number
  hallucinated: number
  rows: EvalRow[]
  recall_sample: number
  recall_curve: { k: number; exact: number; parent: number; current?: boolean }[]
}

export interface Generated {
  ok: boolean
  technique: TechniqueBrief
  language: string
  query: string
  explanation: string
  required_telemetry: string[]
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(body.detail ?? `Request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => call<Health>('/api/health'),
  evalResults: () => call<EvalResults>('/api/eval'),
  seedRules: () => call<{ count: number; rules: SeedRule[] }>('/api/seed-rules'),
  analyze: (rule: string) =>
    call<Analysis>('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ rule, include_gaps: true }),
    }),
  bulkSeed: () =>
    call<BulkResult>('/api/analyze/bulk', {
      method: 'POST',
      body: JSON.stringify({ use_seed: true }),
    }),
  bulkCustom: (rules: { name: string; query: string }[]) =>
    call<BulkResult>('/api/analyze/bulk', {
      method: 'POST',
      body: JSON.stringify({ rules }),
    }),
  generate: (technique_id: string, language: string, context: string) =>
    call<Generated>('/api/generate-rule', {
      method: 'POST',
      body: JSON.stringify({ technique_id, language, context }),
    }),
}
