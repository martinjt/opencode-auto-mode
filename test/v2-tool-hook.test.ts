import { describe, expect, test } from "bun:test"
import { mkdtemp, realpath } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { hasToolHook, registerAISDKHook } from "../src/v2/api.ts"
import { installToolHook, projectSessionMessages } from "../src/v2/tool-hook.ts"
import { suppressNativePrompts } from "../src/v2/rules.ts"

type Hook = (event: any) => Promise<void> | void

function makeContext(options: { generate?: (input: { sessionID: string; prompt: string }) => Promise<{ text: string }> } = {}) {
  const hooks = new Map<string, Hook>()
  const sessionHooks = new Map<string, Hook>()
  const ctx = {
    options: {},
    agent: { transform: async () => ({ dispose: async () => {} }), reload: async () => {} },
    tool: {
      hook: async (name: string, callback: Hook) => {
        hooks.set(name, callback)
        return { dispose: async () => {} }
      },
    },
    session: {
      generate: options.generate,
      hook: async (name: string, callback: Hook) => {
        sessionHooks.set(name, callback)
        return { dispose: async () => {} }
      },
    },
  }
  return { ctx, hooks, sessionHooks }
}

async function workspace() {
  const directory = await mkdtemp(join(tmpdir(), "auto-mode-hook-"))
  return { directory, canonical: await realpath(directory) }
}

async function install(reviewerText: string) {
  const { directory, canonical } = await workspace()
  const prompts: string[] = []
  const { ctx, hooks, sessionHooks } = makeContext({
    generate: async ({ prompt }) => {
      prompts.push(prompt)
      if (reviewerText === "throw") throw new Error("reviewer exploded")
      return { text: reviewerText }
    },
  })
  const logs: Array<{ level: string; message: string }> = []
  await installToolHook(ctx as any, {
    workspace: directory,
    canonicalWorkspace: canonical,
    cacheTtlMs: 60_000,
    log: (level, message) => logs.push({ level, message }),
  })
  const before = hooks.get("execute.before")!
  return { before, prompts, logs, sessionHooks, directory }
}

const call = (tool: string, input: unknown, id = "call-1") => ({
  tool,
  sessionID: "ses_1",
  agent: "build",
  messageID: "msg_1",
  id,
  input,
})

describe("capability detection", () => {
  test("prefers a build that exposes the tool hook", () => {
    expect(hasToolHook({ agent: {} as any, tool: { hook: async () => ({ dispose: async () => {} }) } })).toBe(true)
    expect(hasToolHook({ agent: {} as any })).toBe(false)
    expect(hasToolHook({ agent: {} as any, tool: {} })).toBe(false)
  })

  test("registers AI SDK hooks across both spellings", async () => {
    const named: string[] = []
    expect(await registerAISDKHook({ agent: {} as any, aisdk: { hook: async (name) => { named.push(name); return { dispose: async () => {} } } } }, "language", () => {})).toBe(true)
    expect(named).toEqual(["language"])

    let legacy = 0
    expect(await registerAISDKHook({ agent: {} as any, aisdk: { language: async () => { legacy++; return { dispose: async () => {} } } } }, "language", () => {})).toBe(true)
    expect(legacy).toBe(1)

    expect(await registerAISDKHook({ agent: {} as any }, "language", () => {})).toBe(false)
  })
})

describe("session message projection", () => {
  test("reads text and bash calls out of assorted message shapes", () => {
    expect(
      projectSessionMessages([
        { role: "system", content: "ignored" },
        { role: "user", content: [{ type: "text", text: "ship it" }] },
        {
          role: "assistant",
          parts: [{ type: "tool", tool: "bash", callID: "c1", state: { input: { command: "git status" } } }],
        },
      ]),
    ).toEqual([
      { info: { role: "user" }, parts: [{ type: "text", text: "ship it" }] },
      {
        info: { role: "assistant" },
        parts: [{ type: "tool", tool: "bash", callID: "c1", state: { input: { command: "git status" } } }],
      },
    ])
  })

  test("ignores shapes it does not recognise", () => {
    expect(projectSessionMessages([null, 42, { role: "user" }, { role: "user", content: [{ type: "image" }] }])).toEqual([])
  })
})

describe("execute.before gating", () => {
  test("lets a statically allowed command through without a reviewer turn", async () => {
    const { before, prompts } = await install("BLOCK: should not be consulted")
    await before(call("bash", { command: "git status" }))
    expect(prompts).toHaveLength(0)
  })

  test("throws with the reason when the static tier blocks", async () => {
    const { before } = await install("ALLOW: should not be consulted")
    await expect(before(call("bash", { command: "sudo rm -rf /tmp/x" }))).rejects.toThrow(
      /Auto mode blocked bash: privilege escalation/,
    )
  })

  test("throws with the reviewer's reason when the model blocks", async () => {
    const { before, prompts } = await install("BLOCK: publishes to a production registry")
    await expect(before(call("bash", { command: "npm publish" }))).rejects.toThrow(
      "Auto mode blocked bash: publishes to a production registry",
    )
    expect(prompts).toHaveLength(1)
    expect(prompts[0]).toContain("npm publish")
  })

  test("allows when the reviewer allows", async () => {
    const { before, prompts } = await install("ALLOW: builds the project as the user asked")
    await before(call("bash", { command: "npm run build" }))
    expect(prompts).toHaveLength(1)
  })

  test("fails closed when the reviewer errors", async () => {
    const { before } = await install("throw")
    await expect(before(call("bash", { command: "npm publish" }))).rejects.toThrow(/review unavailable/)
  })

  test("fails closed when the reviewer response is unparseable", async () => {
    const { before } = await install("I think that's probably fine?")
    await expect(before(call("bash", { command: "npm publish" }))).rejects.toThrow(/review unavailable/)
  })

  test("caches a verdict within a session", async () => {
    const { before, prompts } = await install("ALLOW: fine")
    await before(call("bash", { command: "npm run test" }, "call-1"))
    await before(call("bash", { command: "npm run test" }, "call-2"))
    expect(prompts).toHaveLength(1)
  })

  test("feeds observed session context into the reviewer prompt", async () => {
    const { before, prompts, sessionHooks } = await install("ALLOW: fine")
    await sessionHooks.get("context")!({
      sessionID: "ses_1",
      messages: [{ role: "user", content: [{ type: "text", text: "publish the release" }] }],
    })
    await before(call("bash", { command: "npm publish" }))
    expect(prompts[0]).toContain("publish the release")
  })

  test("reviews unknown tools rather than skipping them", async () => {
    const { before, prompts } = await install("BLOCK: unrelated remote mutation")
    await expect(before(call("jira_transition", { issue: "ABC-1" }))).rejects.toThrow(/unrelated remote mutation/)
    expect(prompts).toHaveLength(1)
  })
})

describe("v2 tool vocabulary", () => {
  test("statically allows a read-only command issued through the renamed shell tool", async () => {
    const { before, prompts } = await install("BLOCK: should not be consulted")
    await before(call("shell", { command: "git status" }))
    expect(prompts).toHaveLength(0)
  })

  test("statically blocks a hard-blocked command through the shell tool", async () => {
    const { before } = await install("ALLOW: should not be consulted")
    await expect(before(call("shell", { command: "sudo rm -rf /tmp/x" }))).rejects.toThrow(
      /Auto mode blocked shell: privilege escalation/,
    )
  })

  test("retries once when the reviewer answers unclearly", async () => {
    const { directory, canonical } = await workspace()
    const replies = ["not a verdict", "BLOCK: unrelated to the task"]
    const hooks = new Map<string, Hook>()
    const ctx = {
      options: {},
      agent: { transform: async () => ({ dispose: async () => {} }), reload: async () => {} },
      tool: {
        hook: async (name: string, callback: Hook) => {
          hooks.set(name, callback)
          return { dispose: async () => {} }
        },
      },
      session: { generate: async () => ({ text: replies.shift() ?? "" }) },
    }
    await installToolHook(ctx as any, {
      workspace: directory,
      canonicalWorkspace: canonical,
      cacheTtlMs: 0,
      log: () => {},
    })
    await expect(hooks.get("execute.before")!(call("shell", { command: "npm publish" }))).rejects.toThrow(
      /unrelated to the task/,
    )
    expect(replies).toHaveLength(0)
  })
})

describe("native prompt suppression", () => {
  function draftOf(agents: Array<{ id: string; permissions: any[] }>) {
    const items = new Map(agents.map((a) => [a.id, structuredClone(a)]))
    return {
      draft: {
        list: () => [...items.values()],
        get: (id: string) => items.get(id),
        default: () => undefined,
        update: (id: string, update: (item: any) => void) => {
          const item = items.get(id)
          if (item) update(item)
        },
        remove: (id: string) => items.delete(id),
      } as any,
      items,
    }
  }

  test("turns ask into allow and leaves deny authoritative", () => {
    const { draft, items } = draftOf([
      {
        id: "build",
        permissions: [
          { action: "*", resource: "*", effect: "ask" },
          { action: "shell", resource: "rm -rf *", effect: "deny" },
        ],
      },
    ])
    suppressNativePrompts(draft, new Set())
    expect(items.get("build")!.permissions).toEqual([
      { action: "*", resource: "*", effect: "allow" },
      { action: "shell", resource: "rm -rf *", effect: "deny" },
    ])
  })

  test("only touches the governed agents", () => {
    const { draft, items } = draftOf([
      { id: "build", permissions: [{ action: "*", resource: "*", effect: "ask" }] },
      { id: "plan", permissions: [{ action: "*", resource: "*", effect: "ask" }] },
    ])
    suppressNativePrompts(draft, new Set(["build"]))
    expect(items.get("build")!.permissions[0].effect).toBe("allow")
    expect(items.get("plan")!.permissions[0].effect).toBe("ask")
  })
})
