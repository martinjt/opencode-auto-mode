import { projectConversation, errorMessage, type Decision, type MessageWithParts, type ReviewContext } from "../core.ts"
import { parseInput } from "./context.ts"
import { makeClassifier, type ClassifierDeps } from "./classify.ts"
import type { GateLog } from "./intercept.ts"
import type { PluginContextLike, SessionDomain, ToolDomain } from "./api.ts"
import { parseDecision } from "../core.ts"

export type ToolHookDeps = Omit<ClassifierDeps, "review" | "context"> & {
  /** Reviewer turn. Falls back to the session's own model via `session.generate`. */
  review?: (request: string, sessionID: string) => Promise<{ allowed: boolean; reason: string }>
  log: GateLog
}

/**
 * Projects whatever message shape the build hands to `session.hook("context")`
 * into the reviewer's message model. Only text and bash tool calls matter, and
 * an unrecognised shape simply contributes nothing.
 */
export function projectSessionMessages(messages: unknown[]): MessageWithParts[] {
  const projected: MessageWithParts[] = []
  for (const raw of messages) {
    if (!raw || typeof raw !== "object") continue
    const message = raw as Record<string, any>
    const role = message.role
    if (role !== "user" && role !== "assistant") continue
    const content = Array.isArray(message.content) ? message.content : Array.isArray(message.parts) ? message.parts : []
    const parts: Array<Record<string, unknown>> = []
    for (const item of content) {
      if (!item || typeof item !== "object") continue
      const part = item as Record<string, any>
      if (part.type === "text" && typeof part.text === "string") {
        parts.push({ type: "text", text: part.text })
        continue
      }
      if (part.type !== "tool-call" && part.type !== "tool") continue
      const tool = part.toolName ?? part.tool
      if (typeof tool !== "string") continue
      parts.push({
        type: "tool",
        tool,
        callID: part.toolCallId ?? part.callID ?? part.id,
        state: { input: parseInput(part.input ?? part.args ?? part.state?.input) },
      })
    }
    if (parts.length) projected.push({ info: { role }, parts })
  }
  return projected
}

/**
 * The v1 plugin's interception point, restored: builds that expose
 * `tool.hook("execute.before")` let the classifier run before the tool starts
 * and block by throwing, which puts the reason straight into the tool error the
 * model reads — no permission rules and no deferred explanation needed.
 */
export async function installToolHook(
  ctx: PluginContextLike & { tool: ToolDomain },
  deps: ToolHookDeps,
): Promise<void> {
  const sessions = new Map<string, MessageWithParts[]>()

  const session: SessionDomain | undefined = ctx.session
  if (typeof session?.hook === "function") {
    await session
      .hook("context", (event: { sessionID?: string; messages?: unknown[] }) => {
        if (!event?.sessionID || !Array.isArray(event.messages)) return
        sessions.set(event.sessionID, projectSessionMessages(event.messages))
      })
      .catch((error) => {
        deps.log("warn", "auto mode could not observe session context", { error: errorMessage(error) })
      })
  }

  const contextFor = (sessionID: string, callID: string): ReviewContext => ({
    ...projectConversation(sessions.get(sessionID) ?? [], callID),
    branch: null,
    gitStatus: null,
    projectDoc: null,
  })

  const review = async (request: string, sessionID: string) => {
    if (deps.review) return deps.review(request, sessionID)
    if (typeof session?.generate !== "function") {
      throw new Error("no reviewer available: this build exposes no session.generate and no reviewer model is set")
    }
    // session.generate answers with the session's own model, which sometimes
    // returns nothing or prose instead of the one-line verdict. Ask once more
    // before failing closed; a second unclear answer still blocks.
    const attempt = async (prompt: string) => parseDecision((await session.generate!({ sessionID, prompt })).text ?? "")
    try {
      return await attempt(request)
    } catch (error) {
      deps.log("warn", "auto mode reviewer response was unclear; retrying once", { error: errorMessage(error) })
      return attempt(`${request}\n\nRespond with one line only, in exactly this form: ALLOW: <reason> or BLOCK: <reason>.`)
    }
  }

  const classifier = makeClassifier({
    workspace: deps.workspace,
    canonicalWorkspace: deps.canonicalWorkspace,
    cacheTtlMs: deps.cacheTtlMs,
    review: (request, scope) => review(request, scope.sessionID),
    context: (scope) => contextFor(scope.sessionID, scope.callID),
  })

  await ctx.tool.hook("execute.before", async (event: any) => {
    const args = parseInput(event?.input)
    const scope = { sessionID: String(event?.sessionID ?? ""), callID: String(event?.id ?? "") }

    let decision: Decision
    try {
      decision = await classifier.classify(event?.tool ?? "unknown", args, scope)
    } catch (error) {
      const failure = errorMessage(error)
      deps.log("error", "auto mode review failed; blocking the operation", { tool: event?.tool, error: failure })
      throw new Error(`Auto mode blocked ${event?.tool}: review unavailable: ${failure}`)
    }

    deps.log(decision.allowed ? "debug" : "info", `auto mode ${decision.allowed ? "allowed" : "blocked"} a tool call`, {
      tool: event?.tool,
      source: decision.source,
      reason: decision.reason,
    })
    if (!decision.allowed) throw new Error(`Auto mode blocked ${event?.tool}: ${decision.reason}`)
  })
}
