import { isAbsolute, relative, resolve } from "node:path"
import { realpath } from "node:fs/promises"

import {
  analyzeTool,
  buildReviewRequest,
  inspectToolPaths,
  serializeToolInvocation,
  staticToolDecision,
  type Decision,
  type ReviewContext,
} from "../core.ts"
import type { ReviewOutcome } from "./review.ts"

export type ClassifierDeps = {
  workspace: string
  canonicalWorkspace: string
  cacheTtlMs: number
  /** Runs one reviewer turn. Supplied by the host path so this stays transport-agnostic. */
  review: (request: string, scope: Scope) => Promise<ReviewOutcome>
  /** Conversation context for the reviewer, excluding the call under review. */
  context: (scope: Scope) => ReviewContext | Promise<ReviewContext>
}

/** Identifies the call under review; also scopes the decision cache. */
export type Scope = {
  readonly sessionID: string
  readonly callID: string
}

export type Classifier = {
  classify(tool: string, args: Record<string, unknown>, scope: Scope): Promise<Decision>
}

/**
 * v2 renamed several built-in tools. The classifier's static tiers key off the
 * v1 names — `analyzeCommand` only runs for `bash` — so a v2 `shell` call would
 * otherwise skip both the hard-block list and the conservative allow list and
 * go straight to the reviewer.
 */
const TOOL_ALIASES: Record<string, string> = {
  shell: "bash",
  subagent: "task",
  patch: "apply_patch",
}

export function canonicalToolName(tool: string): string {
  return TOOL_ALIASES[tool] ?? tool
}

/**
 * The three tiers, unchanged from the v1 plugin: a conservative static allow, a
 * static block for hard-blocked behaviour, and an LLM review for everything
 * else. Only the transport around it differs between OpenCode versions.
 */
export function makeClassifier(deps: ClassifierDeps): Classifier {
  const cache = new Map<string, { expires: number; decision: Decision }>()
  const inflight = new Map<string, Promise<Decision>>()

  return {
    async classify(reported, args, scope) {
      // Static tiers reason about the v1 tool vocabulary; messages keep the name
      // the build actually used.
      const tool = canonicalToolName(reported)
      const analysis = analyzeTool(tool, args)
      const pathInspection = await inspectToolPaths(tool, args, deps.workspace, deps.canonicalWorkspace)
      if (pathInspection.external) analysis.behaviors.push("external-path: canonical target is outside the project")
      if (pathInspection.ambiguous) analysis.behaviors.push("ambiguous-path: canonical target could not be verified")

      const staticResult = staticToolDecision(tool, args, analysis, pathInspection)
      let effectiveCwd: string | undefined
      if (!staticResult && tool === "bash") {
        const workdir = typeof args.workdir === "string" && args.workdir.trim() ? args.workdir.trim() : deps.workspace
        const requestedCwd = resolve(deps.workspace, workdir)
        effectiveCwd = await realpath(requestedCwd).catch(() => requestedCwd)
      }

      const serialized = serializeToolInvocation(tool, args, deps.workspace, pathInspection, effectiveCwd)
      if (serialized.incomplete && !staticResult) {
        throw new Error(`auto mode cannot safely review incomplete ${reported} arguments`)
      }
      if (effectiveCwd) {
        const local = relative(deps.canonicalWorkspace, effectiveCwd)
        if (local === ".." || local.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(local)) {
          analysis.behaviors.push("external-path: effective Bash working directory is outside the project")
        }
      }
      if (staticResult) return staticResult

      const key = `${scope.sessionID}\u0000${tool} ${serialized.text}`
      const now = Date.now()
      const cached = cache.get(key)
      if (cached && cached.expires > now) return cached.decision
      const running = inflight.get(key)
      if (running) return running

      const review = (async (): Promise<Decision> => {
        const context = await deps.context(scope)
        const request = buildReviewRequest(serialized.text, reported, deps.workspace, context, analysis)
        const outcome = await deps.review(request, scope)
        return { allowed: outcome.allowed, reason: outcome.reason, source: "llm" }
      })()
        .then((decision) => {
          cache.set(key, { expires: Date.now() + deps.cacheTtlMs, decision })
          return decision
        })
        .finally(() => {
          inflight.delete(key)
        })

      inflight.set(key, review)
      return review
    },
  }
}
