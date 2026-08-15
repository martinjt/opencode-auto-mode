import { describe, expect, test } from "bun:test"
import { mkdtemp, realpath, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3Prompt,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider"
import type { AgentV2Info } from "@opencode-ai/sdk/v2/types"

import { reviewContext, toMessages } from "../src/v2/context.ts"
import { makeGate } from "../src/v2/intercept.ts"
import { grantableResources, makeRuleStore, permissionTarget } from "../src/v2/rules.ts"

const REVIEWER_PROMPT = "You review tool invocations."

function agent(id: string, permissions: AgentV2Info["permissions"] = []): AgentV2Info {
  return {
    id,
    request: { headers: {}, body: {} },
    mode: "primary",
    hidden: false,
    permissions,
  } as AgentV2Info
}

function draftOf(agents: AgentV2Info[]) {
  const items = new Map(agents.map((item) => [item.id, structuredClone(item)]))
  return {
    draft: {
      list: () => [...items.values()],
      get: (id: string) => items.get(id),
      default: () => undefined,
      update: (id: string, update: (item: AgentV2Info) => void) => {
        const item = items.get(id)
        if (item) update(item)
      },
      remove: (id: string) => {
        items.delete(id)
      },
    },
    items,
  }
}

function stubModel(text: string, calls: LanguageModelV3CallOptions[] = []): LanguageModelV3 {
  return {
    specificationVersion: "v3",
    provider: "test",
    modelId: "reviewer",
    supportedUrls: {},
    doGenerate: async (options) => {
      calls.push(options)
      if (text === "throw") throw new Error("reviewer exploded")
      return {
        content: [{ type: "text", text }],
        finishReason: "stop" as const,
        usage: { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } },
        warnings: [],
      }
    },
    doStream: async () => {
      throw new Error("not used")
    },
  } as unknown as LanguageModelV3
}

async function workspace() {
  const directory = await mkdtemp(join(tmpdir(), "auto-mode-v2-"))
  return { directory, canonical: await realpath(directory) }
}

function makeHarness(reviewerText: string, overrides: { fallback?: "ask" | "deny" } = {}) {
  const reloads: number[] = []
  const rules = makeRuleStore({
    ttlMs: 60_000,
    base:
      overrides.fallback === "deny" ? [{ action: "bash", resource: "**", effect: "deny" as const }] : [],
    agents: new Set<string>(),
  })
  const reviewerCalls: LanguageModelV3CallOptions[] = []
  const model = stubModel(reviewerText, reviewerCalls)
  return { reloads, rules, model, reviewerCalls }
}

async function gateOf(reviewerText: string, overrides: { fallback?: "ask" | "deny" } = {}) {
  const { directory, canonical } = await workspace()
  const harness = makeHarness(reviewerText, overrides)
  const gate = makeGate({
    workspace: directory,
    canonicalWorkspace: canonical,
    reviewerPrompt: REVIEWER_PROMPT,
    reviewTimeoutMs: 5_000,
    cacheTtlMs: 60_000,
    rules: harness.rules,
    reload: async () => {
      harness.reloads.push(Date.now())
    },
    log: () => undefined,
  })
  return { gate, directory, canonical, ...harness }
}

const EMPTY_PROMPT: LanguageModelV3Prompt = [{ role: "user", content: [{ type: "text", text: "do the thing" }] }]

function appliedRules(rules: ReturnType<typeof makeRuleStore>, agents = [agent("build")]) {
  const { draft, items } = draftOf(agents)
  rules.apply(draft)
  return items.get(agents[0]!.id)!.permissions
}

describe("permission targets", () => {
  test("maps bash to the command resource", () => {
    expect(permissionTarget("bash", { command: "git status" }, "/work")).toEqual({
      action: "bash",
      resources: ["git status"],
    })
  })

  test("maps write to the edit action with candidate path spellings", () => {
    const target = permissionTarget("write", { path: "src/app.ts" }, "/work")
    expect(target?.action).toBe("edit")
    expect(target?.resources).toContain("src/app.ts")
    expect(target?.resources.some((resource) => resource.endsWith("/work/src/app.ts"))).toBe(true)
  })

  test("maps webfetch to the url resource", () => {
    expect(permissionTarget("webfetch", { url: "https://example.com" }, "/work")?.resources).toEqual([
      "https://example.com",
    ])
  })

  test("returns nothing for tools it cannot target", () => {
    expect(permissionTarget("some_mcp_tool", { anything: true }, "/work")).toBeUndefined()
  })

  test("never grants a resource containing wildcard characters", () => {
    expect(grantableResources({ action: "bash", resources: ["rm -rf *", "ls -la"] })).toEqual(["ls -la"])
  })
})

describe("rule store", () => {
  test("appends recorded decisions to every agent", () => {
    const rules = makeRuleStore({ ttlMs: 60_000, base: [], agents: new Set() })
    rules.record("call-1", { action: "bash", resources: ["git status"] }, "allow")
    expect(appliedRules(rules)).toEqual([{ action: "bash", resource: "git status", effect: "allow" }])
  })

  test("keeps the agent's own rules underneath", () => {
    const rules = makeRuleStore({ ttlMs: 60_000, base: [], agents: new Set() })
    rules.record("call-1", { action: "bash", resources: ["git push"] }, "deny")
    const existing = [{ action: "bash", resource: "*", effect: "ask" as const }]
    expect(appliedRules(rules, [agent("build", existing)])).toEqual([
      { action: "bash", resource: "*", effect: "ask" },
      { action: "bash", resource: "git push", effect: "deny" },
    ])
  })

  test("only governs the configured agents", () => {
    const rules = makeRuleStore({ ttlMs: 60_000, base: [], agents: new Set(["build"]) })
    rules.record("call-1", { action: "bash", resources: ["ls"] }, "allow")
    const { draft, items } = draftOf([agent("build"), agent("plan")])
    rules.apply(draft)
    expect(items.get("build")!.permissions).toHaveLength(1)
    expect(items.get("plan")!.permissions).toHaveLength(0)
  })

  test("expires decisions after their lifetime", () => {
    const rules = makeRuleStore({ ttlMs: 1_000, base: [], agents: new Set() })
    rules.record("call-1", { action: "bash", resources: ["ls"] }, "allow", 0)
    expect(rules.size()).toBe(1)
    rules.evict(2_000)
    expect(rules.size()).toBe(0)
  })

  test("catch-all deny never uses the bare wildcard resource", () => {
    const rules = makeRuleStore({
      ttlMs: 1_000,
      base: [{ action: "bash", resource: "**", effect: "deny" }],
      agents: new Set(),
    })
    expect(appliedRules(rules).every((rule) => rule.resource !== "*")).toBe(true)
  })
})

describe("reviewer context", () => {
  const prompt: LanguageModelV3Prompt = [
    { role: "system", content: "you are an agent" },
    { role: "user", content: [{ type: "text", text: "ship the release" }] },
    {
      role: "assistant",
      content: [
        { type: "text", text: "checking the tree" },
        { type: "tool-call", toolCallId: "call-1", toolName: "bash", input: JSON.stringify({ command: "git status" }) },
      ],
    },
  ]

  test("projects the request into messages", () => {
    expect(toMessages(prompt)).toEqual([
      { info: { role: "user" }, parts: [{ type: "text", text: "ship the release" }] },
      {
        info: { role: "assistant" },
        parts: [
          { type: "text", text: "checking the tree" },
          { type: "tool", tool: "bash", callID: "call-1", state: { input: { command: "git status" } } },
        ],
      },
    ])
  })

  test("carries the original task and prior commands into review context", () => {
    const context = reviewContext(prompt)
    expect(context.firstUser).toBe("ship the release")
    expect(context.recentCommands.join(" ")).toContain("git")
    expect(context.branch).toBeNull()
  })

  test("excludes the call under review from prior commands", () => {
    expect(reviewContext(prompt, "call-1").recentCommands).toEqual([])
  })
})

describe("gating tool calls", () => {
  test("statically allows a conservative read-only command without calling the reviewer", async () => {
    const { gate, rules, reviewerCalls, reloads, model } = await gateOf("BLOCK: should not be consulted")
    await gate.gate(
      { toolCallId: "call-1", toolName: "bash", input: JSON.stringify({ command: "git status" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(reviewerCalls).toHaveLength(0)
    expect(appliedRules(rules)).toEqual([{ action: "bash", resource: "git status", effect: "allow" }])
    expect(reloads).toHaveLength(1)
  })

  test("statically blocks a hard-blocked command", async () => {
    const { gate, rules, reviewerCalls, model } = await gateOf("ALLOW: should not be consulted")
    await gate.gate(
      { toolCallId: "call-2", toolName: "bash", input: JSON.stringify({ command: "sudo rm -rf /tmp/x" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(reviewerCalls).toHaveLength(0)
    expect(appliedRules(rules)[0]?.effect).toBe("deny")
    expect(gate.denials.get("call-2")).toContain("privilege escalation")
  })

  test("allows on a reviewer ALLOW verdict", async () => {
    const { gate, rules, reviewerCalls, model } = await gateOf("ALLOW: builds the project as the user asked")
    await gate.gate(
      { toolCallId: "call-3", toolName: "bash", input: JSON.stringify({ command: "npm run build" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(reviewerCalls).toHaveLength(1)
    expect(appliedRules(rules)).toEqual([{ action: "bash", resource: "npm run build", effect: "allow" }])
  })

  test("denies on a reviewer BLOCK verdict and records the reason", async () => {
    const { gate, rules, model } = await gateOf("BLOCK: publishes to a production registry")
    await gate.gate(
      { toolCallId: "call-4", toolName: "bash", input: JSON.stringify({ command: "npm publish" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(appliedRules(rules)).toEqual([{ action: "bash", resource: "npm publish", effect: "deny" }])
    expect(gate.denials.get("call-4")).toBe("publishes to a production registry")
  })

  test("fails closed when the reviewer is unavailable", async () => {
    const { gate, rules, model } = await gateOf("throw")
    await gate.gate(
      { toolCallId: "call-5", toolName: "bash", input: JSON.stringify({ command: "npm publish" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(appliedRules(rules)[0]?.effect).toBe("deny")
    expect(gate.denials.get("call-5")).toContain("review unavailable")
  })

  test("caches a reviewer verdict across identical operations", async () => {
    const { gate, reviewerCalls, model } = await gateOf("ALLOW: fine")
    const call = { toolName: "bash", input: JSON.stringify({ command: "npm run test" }) }
    await gate.gate({ ...call, toolCallId: "call-6" }, EMPTY_PROMPT, model)
    await gate.gate({ ...call, toolCallId: "call-7" }, EMPTY_PROMPT, model)
    expect(reviewerCalls).toHaveLength(1)
  })

  test("leaves untargetable tools to the configured rules", async () => {
    const { gate, rules, reviewerCalls, reloads, model } = await gateOf("ALLOW: fine")
    await gate.gate(
      { toolCallId: "call-8", toolName: "jira_transition", input: JSON.stringify({ issue: "ABC-1" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(reviewerCalls).toHaveLength(0)
    expect(appliedRules(rules)).toEqual([])
    expect(reloads).toHaveLength(0)
  })

  test("does not grant a rule it cannot express safely", async () => {
    const { gate, rules, model } = await gateOf("ALLOW: tidy up build output")
    await gate.gate(
      { toolCallId: "call-9", toolName: "bash", input: JSON.stringify({ command: "rm -rf build/*" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(appliedRules(rules)).toEqual([])
  })

  test("reviews the file a write targets", async () => {
    const { gate, rules, directory, reviewerCalls, model } = await gateOf("ALLOW: writes a project file")
    await writeFile(join(directory, "notes.md"), "hello")
    await gate.gate(
      { toolCallId: "call-10", toolName: "write", input: JSON.stringify({ path: "notes.md", content: "hi" }) },
      EMPTY_PROMPT,
      model,
    )
    expect(reviewerCalls).toHaveLength(1)
    const applied = appliedRules(rules)
    expect(applied.every((rule) => rule.action === "edit")).toBe(true)
    expect(applied.some((rule) => rule.resource === "notes.md")).toBe(true)
  })
})

describe("model wrapper", () => {
  async function collect(stream: ReadableStream<LanguageModelV3StreamPart>) {
    const parts: LanguageModelV3StreamPart[] = []
    const reader = stream.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      parts.push(value)
    }
    return parts
  }

  test("gates streamed tool calls before passing them through", async () => {
    const { gate, rules } = await gateOf("BLOCK: unrelated to the task")
    const parts: LanguageModelV3StreamPart[] = [
      { type: "stream-start", warnings: [] },
      { type: "tool-input-start", id: "call-1", toolName: "bash" },
      { type: "tool-call", toolCallId: "call-1", toolName: "bash", input: JSON.stringify({ command: "npm publish" }) },
      { type: "finish", finishReason: "tool-calls" as const, usage: { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } } },
    ]
    const underlying = {
      specificationVersion: "v3",
      provider: "test",
      modelId: "session",
      supportedUrls: {},
      doGenerate: async () => {
        throw new Error("not used")
      },
      doStream: async () => ({
        stream: new ReadableStream<LanguageModelV3StreamPart>({
          start(controller) {
            for (const part of parts) controller.enqueue(part)
            controller.close()
          },
        }),
      }),
    } as unknown as LanguageModelV3

    const wrapped = gate.wrap(underlying)
    const result = await wrapped.doStream({ prompt: EMPTY_PROMPT })
    const seen = await collect(result.stream)

    expect(seen.map((part) => part.type)).toEqual(["stream-start", "tool-input-start", "tool-call", "finish"])
    expect(appliedRules(rules)).toEqual([{ action: "bash", resource: "npm publish", effect: "deny" }])
  })

  test("rewrites the blocked tool result so the model sees the reason", async () => {
    const { gate, model } = await gateOf("BLOCK: publishes to a production registry")
    await gate.gate(
      { toolCallId: "call-1", toolName: "bash", input: JSON.stringify({ command: "npm publish" }) },
      EMPTY_PROMPT,
      model,
    )

    const prompt: LanguageModelV3Prompt = [
      { role: "user", content: [{ type: "text", text: "ship it" }] },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call-1",
            toolName: "bash",
            output: { type: "text", value: "Unable to execute command: npm publish" },
          },
        ],
      },
    ]

    const rewritten = gate.rewritePrompt(prompt)
    const result = rewritten[1]!
    const part = (result.content as Array<{ type: string; output?: { type: string; value?: string } }>)[0]!
    expect(part.output?.type).toBe("error-text")
    expect(part.output?.value).toBe("Blocked by auto mode: publishes to a production registry")
  })

  test("leaves untouched prompts alone", async () => {
    const { gate } = await gateOf("ALLOW: fine")
    expect(gate.rewritePrompt(EMPTY_PROMPT)).toBe(EMPTY_PROMPT)
  })
})
