import { readFile, realpath } from "node:fs/promises"
import { resolve } from "node:path"

import type { LanguageModelV3 } from "@ai-sdk/provider"
import { define } from "@opencode-ai/plugin/v2/promise"
import type { PermissionV2Rule } from "@opencode-ai/sdk/v2/types"

import { CACHE_TTL_MS, DEFAULT_REVIEW_TIMEOUT_MS, REVIEWER_PROMPT_URL, errorMessage, parseModel } from "../core.ts"
import { makeGate, type GateLog } from "./intercept.ts"
import { makeRuleStore } from "./rules.ts"

const PLUGIN_ID = "opencode-auto-mode"
const DEFAULT_RULE_TTL_MS = 120_000

/**
 * Actions covered by the catch-all deny when `fallback: "deny"` is configured.
 * The resource is `**` rather than `*`: the tool registry removes any tool whose
 * last matching rule is an exact `*` deny, which would hide the tool from the
 * model instead of gating it.
 */
const GOVERNED_ACTIONS = ["bash", "edit", "read", "webfetch", "websearch", "glob", "grep", "skill"]

function boolOption(options: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const value = options[key]
  if (value === undefined) return fallback
  if (typeof value !== "boolean") throw new TypeError(`auto mode option '${key}' must be a boolean`)
  return value
}

function numberOption(options: Record<string, unknown>, key: string, fallback: number, min: number, max: number) {
  const value = options[key]
  if (value === undefined) return fallback
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) throw new TypeError(`auto mode option '${key}' must be a number`)
  return Math.min(Math.max(parsed, min), max)
}

function stringListOption(options: Record<string, unknown>, key: string): string[] {
  const value = options[key]
  if (value === undefined) return []
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TypeError(`auto mode option '${key}' must be an array of strings`)
  }
  return value as string[]
}

function basePosture(mode: string): PermissionV2Rule[] {
  if (mode === "ask") return []
  if (mode !== "deny") throw new TypeError("auto mode option 'fallback' must be 'ask' or 'deny'")
  return GOVERNED_ACTIONS.map((action) => ({ action, resource: "**", effect: "deny" }))
}

export default define({
  id: PLUGIN_ID,
  setup: async (ctx) => {
    const options = (ctx.options ?? {}) as Record<string, unknown>
    if (!boolOption(options, "enabled", true)) return

    const modelSpec =
      (typeof options.model === "string" ? options.model.trim() : "") ||
      process.env.OPENCODE_AUTO_REVIEWER_MODEL?.trim()
    if (options.model !== undefined && typeof options.model !== "string") {
      throw new TypeError("auto mode option 'model' must use the string format 'provider/model'")
    }
    const reviewerModel = parseModel(modelSpec)
    if (modelSpec && !reviewerModel) {
      throw new TypeError("auto mode option 'model' must use the format 'provider/model'")
    }

    const reviewerPrompt = (await readFile(REVIEWER_PROMPT_URL, "utf8")).trim()
    if (!reviewerPrompt) throw new Error(`auto mode reviewer prompt is empty: ${REVIEWER_PROMPT_URL.pathname}`)

    const workspace = typeof options.workspace === "string" && options.workspace ? options.workspace : process.cwd()
    const canonicalWorkspace = await realpath(workspace).catch(() => resolve(workspace))

    const log: GateLog = (level, message, extra) => {
      const line = `[${PLUGIN_ID}] ${message}${extra ? ` ${JSON.stringify(extra)}` : ""}`
      if (level === "error" || level === "warn") console.error(line)
      else if (process.env.OPENCODE_AUTO_MODE_DEBUG) console.error(line)
    }

    const rules = makeRuleStore({
      ttlMs: numberOption(options, "ruleTtlMs", DEFAULT_RULE_TTL_MS, 5_000, 600_000),
      base: basePosture(typeof options.fallback === "string" ? options.fallback : "ask"),
      agents: new Set(stringListOption(options, "agents")),
    })

    await ctx.agent.transform((draft) => {
      rules.apply(draft)
    })

    let reviewer: LanguageModelV3 | undefined
    const gate = makeGate({
      workspace,
      canonicalWorkspace,
      reviewerPrompt,
      reviewTimeoutMs: numberOption(options, "timeoutMs", DEFAULT_REVIEW_TIMEOUT_MS, 1_000, 300_000),
      cacheTtlMs: numberOption(options, "cacheTtlMs", CACHE_TTL_MS, 0, 3_600_000),
      rules,
      reload: () => ctx.agent.reload(),
      reviewer: () => reviewer,
      log,
    })

    await ctx.aisdk.language((event) => {
      const underlying = event.language
      if (!underlying) return
      // Capture the unwrapped reviewer model first; reviewer turns must not be gated.
      if (reviewerModel && event.model.providerID === reviewerModel.providerID && event.model.id === reviewerModel.modelID) {
        reviewer = underlying
      }
      event.language = gate.wrap(underlying)
    })

    log("info", "auto mode installed", {
      workspace: canonicalWorkspace,
      reviewer: modelSpec || "session model",
    })
  },
})

export { makeGate, makeRuleStore, errorMessage }
