import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { Panel, PanelHead, Chip, Button } from './ui'

/**
 * The sweep's editor. Pre-filled with a realistic starter rule set so the
 * sweep can be run immediately, but every rule is editable and more can be
 * added -- this is the user's rule set, not a fixed demo.
 *
 * The starter rules are pre-analysed on the server, so sweeping them is
 * instant. Anything edited or added is a live model call, and the UI says so.
 */

export interface ParsedRule {
  name: string
  query: string
}

/** Rules are separated by a line of three or more dashes. */
export function splitRules(text: string): ParsedRule[] {
  return text
    .split(/^\s*-{3,}\s*$/m)
    .map((chunk) => chunk.trim())
    .filter((chunk) => chunk.length > 2)
    .map((chunk, i) => {
      // A leading "# name" or "// name" becomes the rule's title.
      const lines = chunk.split('\n')
      const header = lines[0].match(/^\s*(?:#|\/\/)\s*(.+)$/)
      return header
        ? { name: header[1].trim(), query: lines.slice(1).join('\n').trim() }
        : { name: `Rule ${i + 1}`, query: chunk }
    })
    .filter((r) => r.query.length > 2)
}

function toText(rules: { name: string; query: string }[]): string {
  return rules.map((r) => `# ${r.name}\n${r.query}`).join('\n\n---\n\n')
}

const BLANK_TEMPLATE = `# My new rule
index=authentication action=failure
| stats count by src_ip, user
| where count > 20`

export function SweepInput({
  onRun,
  busy,
}: {
  onRun: (rules: ParsedRule[]) => void
  busy: boolean
}) {
  const [text, setText] = useState('')
  const [starter, setStarter] = useState('')
  const [loading, setLoading] = useState(true)
  const fileRef = useRef<HTMLInputElement>(null)
  const areaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    api
      .seedRules()
      .then((d) => {
        const t = toText(d.rules)
        setStarter(t)
        setText(t)
      })
      .catch(() => setText(BLANK_TEMPLATE))
      .finally(() => setLoading(false))
  }, [])

  const parsed = splitRules(text)
  const edited = starter !== '' && text !== starter

  function loadFile(file: File) {
    file.text().then(setText)
  }

  function addRule() {
    const next = text.trimEnd() + '\n\n---\n\n' + BLANK_TEMPLATE
    setText(next)
    requestAnimationFrame(() => {
      const el = areaRef.current
      if (el) {
        el.focus()
        el.scrollTop = el.scrollHeight
        el.setSelectionRange(next.length, next.length)
      }
    })
  }

  return (
    <Panel scanning={busy}>
      <PanelHead
        title="Your detection rules"
        right={
          <div className="flex items-center gap-1.5">
            <Chip tone={parsed.length ? 'phosphor' : 'neutral'} size="sm">
              {parsed.length} rule{parsed.length === 1 ? '' : 's'}
            </Chip>
            {edited ? (
              <Chip tone="amber" size="sm">edited — live calls</Chip>
            ) : (
              <Chip size="sm">pre-analysed</Chip>
            )}
          </div>
        }
      />

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-2.5">
        <p className="text-[12px] text-ink-dim">
          Separate rules with <code className="font-mono text-phosphor">---</code>. A leading{' '}
          <code className="font-mono text-phosphor">#&nbsp;name</code> line becomes the title. Edit
          any of these or add your own.
        </p>
        <div className="flex items-center gap-1.5">
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.md,.spl,.kql,.yml,.yaml,.conf"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && loadFile(e.target.files[0])}
          />
          <Button size="sm" variant="ghost" onClick={addRule}>+ add rule</Button>
          <Button size="sm" variant="ghost" onClick={() => fileRef.current?.click()}>
            upload
          </Button>
          {edited && (
            <Button size="sm" variant="ghost" onClick={() => setText(starter)}>
              reset
            </Button>
          )}
        </div>
      </div>

      <textarea
        ref={areaRef}
        value={loading ? 'loading rules…' : text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        rows={20}
        className="w-full resize-y border-0 bg-void/70 px-5 py-4 font-mono text-[12.5px] leading-[1.7] text-ink placeholder:text-ink-faint"
      />

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-5 py-3">
        <span className="font-mono text-[10px] text-ink-faint">
          {edited
            ? 'changed rules are analysed live (~5s each)'
            : 'unchanged rules return instantly from cache'}
        </span>
        <Button onClick={() => onRun(parsed)} disabled={busy || parsed.length === 0}>
          {busy ? `analysing ${parsed.length}…` : `sweep ${parsed.length} rules ▸`}
        </Button>
      </div>

      {parsed.length > 0 && !loading && (
        <div className="border-t border-line px-5 py-3">
          <div className="label mb-2">will analyse</div>
          <div className="flex flex-wrap gap-1.5">
            {parsed.map((r, i) => (
              <Chip key={i} size="sm">{r.name}</Chip>
            ))}
          </div>
        </div>
      )}
    </Panel>
  )
}
