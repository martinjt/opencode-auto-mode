import { lstat, readFile, realpath, stat } from "node:fs/promises"
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path"

import type { Plugin } from "@opencode-ai/plugin"

import {
  SERVICE,
  REVIEWER_AGENT,
  DEFAULT_REVIEW_TIMEOUT_MS,
  CACHE_TTL_MS,
  REVIEWER_PROMPT_URL,
  ModelRef,
  PermissionRequest,
  PermissionAskedEvent,
  Analysis,
  Decision,
  PermissionAction,
  PermissionRules,
  truncate,
  redactShellCommandProjection,
  errorMessage,
  withTimeout,
  parseModel,
  removeNativePrompts,
  inspectToolPaths,
  serializeToolInvocation,
  analyzeTool,
  staticToolDecision,
  gatherContext,
  analyzeCommand,
  staticDecision,
  buildReviewRequest,
  parseDecision,
  reviewCacheKey,
} from "./core.ts"
export default (async ({ client, directory, $ }, options) => {
  if (options?.enabled !== undefined && typeof options.enabled !== "boolean") {
    throw new TypeError("auto-reviewer option 'enabled' must be a boolean")
  }
  if (options?.enabled === false) return {}
  if (options?.model !== undefined && typeof options.model !== "string") {
    throw new TypeError("auto-reviewer option 'model' must use the string format 'provider/model'")
  }

  const reviewerPrompt = (await readFile(REVIEWER_PROMPT_URL, "utf8")).trim()
  if (!reviewerPrompt) throw new Error(`auto-reviewer prompt is empty: ${REVIEWER_PROMPT_URL.pathname}`)
  const canonicalWorkspace = await realpath(directory).catch(() => resolve(directory))

  const configuredModelSpec =
    (typeof options?.model === "string" ? options.model.trim() : "") || process.env.OPENCODE_AUTO_REVIEWER_MODEL?.trim()
  const configuredModel = parseModel(configuredModelSpec)
  if (configuredModelSpec && !configuredModel) {
    throw new TypeError("auto-reviewer option 'model' must use the format 'provider/model'")
  }
  const configuredTimeout = Number(
    (typeof options?.timeoutMs === "number" || typeof options?.timeoutMs === "string" ? options.timeoutMs : undefined) ??
      process.env.OPENCODE_AUTO_REVIEWER_TIMEOUT_MS,
  )
  const reviewTimeoutMs = Number.isFinite(configuredTimeout)
    ? Math.min(Math.max(configuredTimeout, 1_000), 300_000)
    : DEFAULT_REVIEW_TIMEOUT_MS
  const cache = new Map<string, { expires: number; decision: Decision }>()
  const pending = new Map<string, Promise<Decision>>()
  let fallbackModel: ModelRef | undefined

  async function log(level: "debug" | "info" | "warn" | "error", message: string, extra?: Record<string, unknown>) {
    try {
      await client.app.log({ body: { service: SERVICE, level, message, extra } })
    } catch {
      // Logging must never affect permission handling.
    }
  }

  async function notify(message: string, variant: "info" | "success" | "warning" | "error") {
    try {
      await client.tui.showToast({
        body: {
          title: "Auto reviewer",
          message: truncate(message, 500),
          variant,
          duration: variant === "info" ? 3_000 : 6_000,
        },
      })
    } catch {
      // Headless clients do not necessarily have a TUI attached.
    }
  }

  async function reviewWithLLM(
    command: string,
    permission: string,
    sessionID: string,
    callID: string | undefined,
    analysis: Analysis,
  ): Promise<Decision> {
    await notify(`Reviewing: ${truncate(command, 120)}`, "info")
    const context = await gatherContext(client, $, directory, sessionID, callID)
    const model = configuredModel ?? context.model ?? fallbackModel
    const created = await client.session.create({
      body: { parentID: sessionID, title: `Auto review: ${truncate(command, 60)}` },
    })
    if (created.error || !created.data?.id) {
      throw new Error(`Could not create reviewer session: ${errorMessage(created.error)}`)
    }

    const reviewerSessionID = created.data.id
    let completed = false
    try {
      const response = await withTimeout(
        client.session.prompt({
          path: { id: reviewerSessionID },
          body: {
            agent: REVIEWER_AGENT,
            ...(model ? { model } : {}),
            parts: [
              {
                type: "text",
                text: buildReviewRequest(command, permission, directory, context, analysis),
              },
            ],
          },
        }),
        reviewTimeoutMs,
        "LLM command review",
      )
      completed = true
      if (response.error || !response.data) {
        throw new Error(`Reviewer request failed: ${errorMessage(response.error)}`)
      }
      const text = response.data.parts
        .filter((part) => part.type === "text")
        .map((part) => part.text)
        .join("\n")
      const decision = parseDecision(text)
      return { ...decision, source: "llm" }
    } finally {
      if (!completed) {
        try {
          await client.session.abort({ path: { id: reviewerSessionID } })
        } catch {
          // Best-effort cleanup after a timeout or failed review.
        }
      }
      try {
        await client.session.delete({ path: { id: reviewerSessionID } })
      } catch {
        // Reviewer sessions are disposable and cleanup is best effort.
      }
    }
  }

  async function decide(
    operation: string,
    permission: string,
    sessionID: string,
    callID?: string,
    analysis: Analysis = analyzeCommand(operation),
    staticResult: Decision | null = staticDecision(operation, permission, analysis),
  ): Promise<Decision> {
    const key = reviewCacheKey(sessionID, operation, callID)
    const now = Date.now()
    for (const [cacheKey, entry] of cache) {
      if (entry.expires <= now) cache.delete(cacheKey)
    }
    const cached = cache.get(key)
    if (cached) return cached.decision
    const active = pending.get(key)
    if (active) return active

    const review = (async () => {
      if (staticResult) return staticResult
      return reviewWithLLM(operation, permission, sessionID, callID, analysis)
    })()
    pending.set(key, review)
    try {
      const decision = await review
      cache.set(key, { expires: Date.now() + CACHE_TTL_MS, decision })
      return decision
    } finally {
      pending.delete(key)
    }
  }

  async function reportDecision(decision: Decision) {
    if (decision.source === "static-allow") return
    await notify(
      `${decision.allowed ? "Allowed" : "Blocked"}: ${decision.reason}`,
      decision.allowed ? "success" : "warning",
    )
  }

  async function handlePermissionEvent(request: PermissionRequest) {
    if (!["bash", "external_directory"].includes(request.permission)) return
    const command = request.metadata.command
    if (typeof command !== "string" || !command.trim()) return

    try {
      const rawCommand = command.trim()
      const analysis = analyzeCommand(rawCommand)
      const staticResult = staticDecision(rawCommand, request.permission, analysis)
      const projection = redactShellCommandProjection(rawCommand)
      if (projection.incomplete && !staticResult) {
        throw new Error("Auto-reviewer cannot safely review an incomplete permission request")
      }
      const decision = await decide(
        projection.text,
        request.permission,
        request.sessionID,
        request.tool?.callID,
        analysis,
        staticResult,
      )
      const reply = await client.postSessionIdPermissionsPermissionId({
        path: { id: request.sessionID, permissionID: request.id },
        body: { response: decision.allowed ? "once" : "reject" },
      })
      if (reply.error) {
        await log("debug", "Permission was answered before auto-review completed", {
          requestID: request.id,
          error: errorMessage(reply.error),
        })
        return
      }
      await reportDecision(decision)
    } catch (error) {
      const failure = errorMessage(error)
      await log("error", "Automatic command review failed; blocking the command", {
        requestID: request.id,
        error: failure,
      })
      const reply = await client.postSessionIdPermissionsPermissionId({
        path: { id: request.sessionID, permissionID: request.id },
        body: { response: "reject" },
      })
      if (reply.error) {
        await log("error", "Could not reject permission after reviewer failure", {
          requestID: request.id,
          error: errorMessage(reply.error),
        })
      }
      await notify(`Review failed; command blocked. ${failure}`, "error")
    }
  }

  return {
    config: async (config) => {
      config.permission = removeNativePrompts(config.permission as PermissionAction | PermissionRules | undefined)

      for (const agent of Object.values(config.agent ?? {})) {
        if (!agent) continue
        const permission = agent.permission
        if (!permission) continue
        agent.permission = removeNativePrompts(permission as PermissionAction | PermissionRules)
      }

      fallbackModel = configuredModel ?? parseModel(config.small_model) ?? parseModel(config.model)
      const existingAgent = config.agent?.[REVIEWER_AGENT]
      config.agent = {
        ...config.agent,
        [REVIEWER_AGENT]: {
          ...existingAgent,
          description: "Hidden tool-free agent that reviews OpenCode tool invocations.",
          mode: "subagent",
          hidden: true,
          steps: 1,
          permission: { "*": "deny" } as never,
          prompt: reviewerPrompt,
          ...(configuredModelSpec ? { model: configuredModelSpec } : {}),
        },
      }
    },
    "tool.execute.before": async (input, output) => {
      const args = output.args && typeof output.args === "object" ? (output.args as Record<string, unknown>) : {}
      const analysis = analyzeTool(input.tool, args)
      const pathInspection = await inspectToolPaths(input.tool, args, directory, canonicalWorkspace)
      if (pathInspection.external) analysis.behaviors.push("external-path: canonical target is outside the project")
      if (pathInspection.ambiguous) analysis.behaviors.push("ambiguous-path: canonical target could not be verified")
      const staticResult = staticToolDecision(input.tool, args, analysis, pathInspection)
      let effectiveCwd: string | undefined
      if (!staticResult && input.tool === "bash") {
        const workdir = typeof args.workdir === "string" && args.workdir.trim() ? args.workdir.trim() : directory
        const requestedCwd = resolve(directory, workdir)
        effectiveCwd = await realpath(requestedCwd).catch(() => requestedCwd)
      }
      const serialized = serializeToolInvocation(input.tool, args, directory, pathInspection, effectiveCwd)
      if (serialized.incomplete && !staticResult) {
        throw new Error(`Auto-reviewer cannot safely review incomplete ${input.tool} arguments; operation blocked`)
      }
      const operation = serialized.text
      if (effectiveCwd) {
        const local = relative(canonicalWorkspace, effectiveCwd)
        if (local === ".." || local.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(local)) {
          analysis.behaviors.push("external-path: effective Bash working directory is outside the project")
        }
      }
      let decision: Decision
      try {
        decision = await decide(operation, input.tool, input.sessionID, input.callID, analysis, staticResult)
      } catch (error) {
        const failure = errorMessage(error)
        await log("error", "Pre-execution tool review failed; blocking the operation", {
          tool: input.tool,
          callID: input.callID,
          error: failure,
        })
        await notify(`Review failed; ${input.tool} blocked. ${failure}`, "error")
        throw new Error(`Auto-reviewer unavailable; ${input.tool} operation blocked: ${failure}`)
      }

      await reportDecision(decision)
      if (!decision.allowed) {
        await log("info", "Pre-execution tool review blocked the operation", {
          tool: input.tool,
          callID: input.callID,
          reason: decision.reason,
        })
        throw new Error(`Auto-reviewer blocked ${input.tool}: ${decision.reason}`)
      }
    },
    "permission.ask": async (input, output) => {
      if (!["bash", "external_directory"].includes(input.type)) return
      const command = input.metadata.command
      if (typeof command !== "string" || !command.trim()) return
      try {
        const rawCommand = command.trim()
        const analysis = analyzeCommand(rawCommand)
        const staticResult = staticDecision(rawCommand, input.type, analysis)
        const projection = redactShellCommandProjection(rawCommand)
        if (projection.incomplete && !staticResult) {
          throw new Error("Auto-reviewer cannot safely review an incomplete permission request")
        }
        const decision = await decide(
          projection.text,
          input.type,
          input.sessionID,
          input.callID,
          analysis,
          staticResult,
        )
        output.status = decision.allowed ? "allow" : "deny"
        await reportDecision(decision)
      } catch (error) {
        const failure = errorMessage(error)
        output.status = "deny"
        await log("error", "Permission hook review failed; blocking the command", {
          error: failure,
        })
        await notify(`Review failed; command blocked. ${failure}`, "error")
      }
    },
    event: async ({ event }) => {
      const permissionEvent = event as unknown as PermissionAskedEvent
      if (permissionEvent.type !== "permission.asked") return
      await handlePermissionEvent(permissionEvent.properties)
    },
  }
}) satisfies Plugin
