/**
 * Structural views of the OpenCode v2 plugin context.
 *
 * The shipping v2 builds and the published `@opencode-ai/plugin` beta typings
 * disagree about the context: newer builds carry `tool`, `session`, `event` and
 * `shell` domains and address AI SDK hooks as `aisdk.hook(name, callback)`,
 * while the beta typings expose only nine domains with `aisdk.language(...)`.
 * Describing just the parts this plugin touches — and detecting them at
 * runtime — keeps one source working across both.
 */

export type Registration = { readonly dispose: () => Promise<void> }

export type ToolExecuteBefore = {
  readonly tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

export type SessionContextEvent = {
  readonly sessionID: string
  readonly agent: string
  messages: unknown[]
}

export type ToolDomain = {
  readonly hook: (
    name: "execute.before" | "execute.after",
    callback: (event: any) => Promise<void> | void,
  ) => Promise<Registration>
}

export type SessionDomain = {
  readonly generate?: (input: { sessionID: string; prompt: string }) => Promise<{ text: string }>
  readonly hook?: (name: string, callback: (event: any) => Promise<void> | void) => Promise<Registration>
}

export type AgentDomain = {
  readonly transform: (callback: (draft: any) => Promise<void> | void) => Promise<Registration>
  readonly reload: () => Promise<void>
}

export type AISDKDomain = {
  /** Newer builds: `hook("language", cb)`. */
  readonly hook?: (name: string, callback: (event: any) => Promise<void> | void) => Promise<Registration>
  /** Beta typings: `language(cb)`. */
  readonly language?: (callback: (event: any) => Promise<void> | void) => Promise<Registration>
}

export type PluginContextLike = {
  readonly options?: Record<string, unknown>
  readonly agent: AgentDomain
  readonly aisdk?: AISDKDomain
  readonly tool?: Partial<ToolDomain>
  readonly session?: SessionDomain
}

/** True when the build exposes the tool-execution hook this plugin prefers. */
export function hasToolHook(ctx: PluginContextLike): ctx is PluginContextLike & { tool: ToolDomain } {
  return typeof ctx.tool?.hook === "function"
}

/** Registers an AI SDK hook across both spellings. Returns false when unsupported. */
export async function registerAISDKHook(
  ctx: PluginContextLike,
  name: "language" | "sdk",
  callback: (event: any) => Promise<void> | void,
): Promise<boolean> {
  const aisdk = ctx.aisdk
  if (!aisdk) return false
  if (typeof aisdk.hook === "function") {
    await aisdk.hook(name, callback)
    return true
  }
  if (name === "language" && typeof aisdk.language === "function") {
    await aisdk.language(callback)
    return true
  }
  return false
}
