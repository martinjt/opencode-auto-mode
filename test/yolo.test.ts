import { describe, expect, test } from "bun:test"

import { executeBefore, makeHooks } from "./harness.ts"

const YOLO = { yolo: true }

describe("yolo mode", () => {
  test("rejects a non-boolean yolo option", async () => {
    await expect(
      makeHooks("ALLOW: unused", [], "/workspace/project", [], [], [], { yolo: "yes" }),
    ).rejects.toThrow("'yolo' must be a boolean")
  })

  test("runs an otherwise reviewable command without contacting the reviewer", async () => {
    const { hooks, state } = await makeHooks("BLOCK: reviewer must not run", [], "/workspace/project", [], [], [], YOLO)

    await executeBefore(hooks, "bash", { command: "npm install left-pad" })

    expect(state.promptCalls).toBe(0)
  })

  test("runs external, network, and destructive project operations without review", async () => {
    const { hooks, state } = await makeHooks("BLOCK: reviewer must not run", [], "/workspace/project", [], [], [], YOLO)

    await executeBefore(hooks, "read", { filePath: "/outside/project/file.txt" })
    await executeBefore(hooks, "bash", { command: "curl https://example.test/api" })
    await executeBefore(hooks, "bash", { command: "git push --force origin main" })

    expect(state.promptCalls).toBe(0)
  })

  test("runs commands whose arguments cannot be safely serialized for review", async () => {
    const { hooks, state } = await makeHooks("BLOCK: reviewer must not run", [], "/workspace/project", [], [], [], YOLO)

    await executeBefore(hooks, "bash", {
      command: "curl -H 'Authorization: Bearer SYNTHETIC_TOKEN' https://example.test/api",
    })

    expect(state.promptCalls).toBe(0)
  })

  test("still blocks system-destructive commands", async () => {
    const { hooks } = await makeHooks("ALLOW: reviewer must not run", [], "/workspace/project", [], [], [], YOLO)

    await expect(executeBefore(hooks, "bash", { command: "sudo apt-get install nmap" })).rejects.toThrow(
      "privilege escalation is not auto-approved",
    )
    await expect(executeBefore(hooks, "bash", { command: "rm -rf /" })).rejects.toThrow(
      "recursive deletion targets the filesystem root",
    )
    await expect(executeBefore(hooks, "bash", { command: "mkfs.ext4 /dev/sda1" })).rejects.toThrow(
      "filesystem formatting command detected",
    )
  })

  test("answers the permission hook without review and keeps hard blocks", async () => {
    const { hooks } = await makeHooks("BLOCK: reviewer must not run", [], "/workspace/project", [], [], [], YOLO)
    const hook = hooks["permission.ask"]
    if (!hook) throw new Error("permission.ask hook is missing")

    const allowed = { status: "ask" }
    await hook(
      { type: "bash", sessionID: "session", callID: "call", metadata: { command: "npm install left-pad" } } as never,
      allowed as never,
    )
    const blocked = { status: "ask" }
    await hook(
      { type: "bash", sessionID: "session", callID: "call-2", metadata: { command: "shutdown now" } } as never,
      blocked as never,
    )

    expect(allowed.status).toBe("allow")
    expect(blocked.status).toBe("deny")
  })

  test("can be enabled through the environment", async () => {
    process.env.OPENCODE_AUTO_REVIEWER_YOLO = "1"
    try {
      const { hooks, state } = await makeHooks("BLOCK: reviewer must not run")

      await executeBefore(hooks, "bash", { command: "npm install left-pad" })

      expect(state.promptCalls).toBe(0)
    } finally {
      delete process.env.OPENCODE_AUTO_REVIEWER_YOLO
    }
  })

  test("reviews normally when yolo mode is off", async () => {
    const { hooks, state } = await makeHooks("ALLOW: authorized test operation")

    await executeBefore(hooks, "bash", { command: "npm install left-pad" })

    expect(state.promptCalls).toBe(1)
  })
})
