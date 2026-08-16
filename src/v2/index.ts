import { readFile, realpath } from "node:fs/promises"
import { resolve } from "node:path"

import type { LanguageModelV3 } from "@ai-sdk/provider"

import { CACHE_TTL_MS, DEFAULT_REVIEW_TIMEOUT_MS, REVIEWER_PROMPT_URL, errorMessage, parseModel } from "../core.ts"
import { hasToolHook, registerAISDKHook, type PluginContextLike } from "./api.ts"
import { makeGate, type GateLog } from "./intercept.ts"
import { requestReview } from "./review.ts"
import { makeRuleStore, suppressNativePrompts } from "./rules.ts"
import { installToolHook } from "./tool-hook.ts"

const PLUGIN_ID = "opencode-auto-mode"
const DEFAULT_RULE_TTL_MS = 120_000

/**
 * Actions covered by the catch-all deny when `fallback: "deny"` is configured on
 * the permission-rule path. The resource is `**` rather than `*`: the tool
 * registry removes any tool whose last matching rule is an exact `*` deny, which
 * would hide the tool from the model instead of gating it.
 */
const GOVERNED_ACTIONS = ["bash", "edit", "read", "webfetch", "websearch", "glob", "grep", "skill"]

type Rule = { action: string; resource: string; effect: "allow" | "ask" | "deny" }

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

function basePosture(mode: string): Rule[] {
  if (mode === "ask") return []
  if (mode !== "deny") throw new TypeError("auto mode option 'fallback' must be 'ask' or 'deny'")
  return GOVERNED_ACTIONS.map((action) => ({ action, resource: "**", effect: "deny" }))
}

export const plugin = {
  id: PLUGIN_ID,
  setup: async (context: unknown) => {
    const ctx = context as PluginContextLike
    const options = (ctx.options ?? {}) as Record<string, unknown>
    if (!boolOption(options, "enabled", true)) return

    if (options.model !== undefined && typeof options.model !== "string") {
      throw new TypeError("auto mode option 'model' must use the string format 'provider/model'")
    }
    const modelSpec =
      (typeof options.model === "string" ? options.model.trim() : "") ||
      process.env.OPENCODE_AUTO_REVIEWER_MODEL?.trim()
    const reviewerModel = parseModel(modelSpec)
    if (modelSpec && !reviewerModel) {
      throw new TypeError("auto mode option 'model' must use the format 'provider/model'")
    }

    const reviewerPrompt = (await readFile(REVIEWER_PROMPT_URL, "utf8")).trim()
    if (!reviewerPrompt) throw new Error(`auto mode reviewer prompt is empty: ${REVIEWER_PROMPT_URL.pathname}`)

    const workspace = typeof options.workspace === "string" && options.workspace ? options.workspace : process.cwd()
    const canonicalWorkspace = await realpath(workspace).catch(() => resolve(workspace))
    const reviewTimeoutMs = numberOption(options, "timeoutMs", DEFAULT_REVIEW_TIMEOUT_MS, 1_000, 300_000)
    const cacheTtlMs = numberOption(options, "cacheTtlMs", CACHE_TTL_MS, 0, 3_600_000)

    const log: GateLog = (level, message, extra) => {
      const line = `[${PLUGIN_ID}] ${message}${extra ? ` ${JSON.stringify(extra)}` : ""}`
      if (level === "error" || level === "warn") console.error(line)
      else if (process.env.OPENCODE_AUTO_MODE_DEBUG) console.error(line)
    }

    // A configured reviewer model is captured, never wrapped: reviewer turns
    // must not re-enter the classifier.
    let reviewer: LanguageModelV3 | undefined
    const captureReviewer = async (wrapForGating?: (model: LanguageModelV3) => LanguageModelV3) =>
      registerAISDKHook(ctx, "language", (event: any) => {
        const underlying = event?.language
        if (!underlying) return
        if (
          reviewerModel &&
          (event.model?.providerID ?? event.model?.provider) === reviewerModel.providerID &&
          event.model?.id === reviewerModel.modelID
        ) {
          reviewer = underlying
        }
        if (wrapForGating) event.language = wrapForGating(underlying)
      })

    const governed = new Set(stringListOption(options, "agents"))

    /**
     * Registering a transform that mutates its domain schedules a rebuild, and
     * during plugin boot that rebuild is batched behind setup itself: awaiting
     * the registration deadlocks the load. Register it and let it settle on its
     * own — the plugin has nothing to do with the result.
     */
    const register = (registration: Promise<unknown>) => {
      void registration.catch((error) => {
        log("error", "auto mode could not register a domain transform", { error: errorMessage(error) })
      })
    }

    if (hasToolHook(ctx)) {
      // Off by default: on the builds tested, the permission prompt is not
      // gated by the agent ruleset, so this rewrite is inert there — and a
      // blanket ask→allow is too security-relevant to apply on spec. Set the
      // base posture in config instead (see the README) and leave this for
      // builds where agent rules do decide.
      if (boolOption(options, "suppressPrompts", false)) {
        register(
          ctx.agent.transform((draft) => {
            suppressNativePrompts(draft, governed)
          }),
        )
      }
      if (reviewerModel) await captureReviewer()
      await installToolHook(ctx, {
        workspace,
        canonicalWorkspace,
        cacheTtlMs,
        log,
        ...(reviewerModel
          ? {
              review: async (request: string) => {
                if (!reviewer) throw new Error(`reviewer model ${modelSpec} has not been resolved yet`)
                return requestReview(reviewer, reviewerPrompt, request, reviewTimeoutMs)
              },
            }
          : {}),
      })
      log("info", "auto mode installed on the tool-execution hook", {
        workspace: canonicalWorkspace,
        reviewer: modelSpec || "session model",
      })
      return
    }

    // Fallback for builds whose plugin context has no tool domain: decide at the
    // language-model boundary and record the verdict as a permission rule.
    const rules = makeRuleStore({
      ttlMs: numberOption(options, "ruleTtlMs", DEFAULT_RULE_TTL_MS, 5_000, 600_000),
      base: basePosture(typeof options.fallback === "string" ? options.fallback : "ask"),
      agents: governed,
    })
    register(
      ctx.agent.transform((draft) => {
        rules.apply(draft)
      }),
    )

    const gate = makeGate({
      workspace,
      canonicalWorkspace,
      reviewerPrompt,
      reviewTimeoutMs,
      cacheTtlMs,
      rules,
      reload: () => ctx.agent.reload(),
      reviewer: () => reviewer,
      log,
    })

    const installed = await captureReviewer((model) => gate.wrap(model))
    if (!installed) {
      throw new Error("auto mode found neither a tool-execution hook nor an AI SDK hook on this OpenCode build")
    }
    log("info", "auto mode installed on the language-model boundary", {
      workspace: canonicalWorkspace,
      reviewer: modelSpec || "session model",
    })
  },
}

export default plugin

export { makeGate, makeRuleStore, errorMessage }
