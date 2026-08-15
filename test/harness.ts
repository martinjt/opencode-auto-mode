import autoMode from "../src/index.ts"

export type MockState = {
  promptCalls: number
  reviewerRequests: string[]
  permissionResponses: string[]
}

export function makeShell(outputs: string[] = []) {
  return (() => {
    const hasOutput = outputs.length > 0
    const output = outputs.shift() ?? ""
    const promise = Promise.resolve({
      exitCode: hasOutput ? 0 : 1,
      text: () => output,
    }) as Promise<{ exitCode: number; text(): string }> & {
      cwd(path: string): unknown
      quiet(): unknown
      nothrow(): unknown
    }
    promise.cwd = () => promise
    promise.quiet = () => promise
    promise.nothrow = () => promise
    return promise
  }) as never
}

export async function makeHooks(
  reviewerText = "ALLOW: authorized test operation",
  userMessages: string[] = [],
  directory = "/workspace/project",
  priorCommands: string[] = [],
  assistantMessages: string[] = [],
  gitOutputs: string[] = [],
  pluginOptions: Record<string, unknown> = {},
) {
  const state: MockState = { promptCalls: 0, reviewerRequests: [], permissionResponses: [] }
  const client = {
    app: {
      log: async () => ({ data: true }),
    },
    tui: {
      showToast: async () => ({ data: true }),
    },
    session: {
      messages: async () => ({
        data: [
          ...userMessages.map((text, index) => ({
            info: { id: `user-${index}`, role: "user" },
            parts: [{ type: "text", text }],
          })),
          ...assistantMessages.map((text, index) => ({
            info: { id: `assistant-text-${index}`, role: "assistant" },
            parts: [{ type: "text", text }],
          })),
          ...priorCommands.map((command, index) => ({
            info: { id: `assistant-${index}`, role: "assistant" },
            parts: [
              {
                type: "tool",
                tool: "bash",
                callID: `prior-call-${index}`,
                state: { input: { command } },
              },
            ],
          })),
        ],
      }),
      create: async () => ({ data: { id: "review-session" } }),
      prompt: async (request: { body?: { parts?: Array<{ text?: string }> } }) => {
        state.promptCalls += 1
        state.reviewerRequests.push(request.body?.parts?.[0]?.text ?? "")
        return {
          data: {
            parts: [{ type: "text", text: reviewerText }],
          },
        }
      },
      abort: async () => ({ data: true }),
      delete: async () => ({ data: true }),
    },
    postSessionIdPermissionsPermissionId: async (request: { body?: { response?: string } }) => {
      state.permissionResponses.push(request.body?.response ?? "")
      return { data: true }
    },
  }
  const hooks = await autoMode(
    {
      client,
      directory,
      worktree: directory,
      project: { id: "project" },
      serverUrl: new URL("http://localhost:4096"),
      $: makeShell(gitOutputs),
    } as never,
    { enabled: true, model: "openai/test-model", ...pluginOptions },
  )
  return { hooks, state }
}

export async function executeBefore(
  hooks: Awaited<ReturnType<typeof autoMode>>,
  tool: string,
  args: Record<string, unknown>,
) {
  const hook = hooks["tool.execute.before"]
  if (!hook) throw new Error("tool.execute.before hook is missing")
  return hook({ tool, sessionID: "session", callID: "call" }, { args })
}
