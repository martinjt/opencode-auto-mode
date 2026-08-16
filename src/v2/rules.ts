import { isAbsolute, relative, resolve } from "node:path"

import type { AgentDraft } from "@opencode-ai/plugin/v2/promise"
import type { PermissionV2Rule } from "@opencode-ai/sdk/v2/types"

import { extractPatchPaths } from "../core.ts"

/**
 * OpenCode v2 resolves an agent's ruleset on every `PermissionV2.assert`, so a
 * rule written just before a tool call is observed by that call. Rules are glob
 * patterns with no escape syntax, so a resource containing `*` or `?` would
 * match more than the operation we reviewed. Those are never granted; they fall
 * through to the user's own configuration instead.
 */
const GLOB = /[*?]/

/** Tool name to the permission action the built-in v2 tool asserts. */
const TOOL_ACTIONS: Record<string, string> = {
  apply_patch: "edit",
  bash: "bash",
  patch: "edit",
  shell: "shell",
  edit: "edit",
  glob: "glob",
  grep: "grep",
  read: "read",
  skill: "skill",
  webfetch: "webfetch",
  websearch: "websearch",
  write: "edit",
}

/** Tools whose permission resource is a filesystem path we must re-derive. */
const PATH_TOOLS = new Set(["apply_patch", "edit", "read", "write"])

export type Verdict = "allow" | "deny"

export type PermissionTarget = {
  action: string
  /**
   * Every spelling of the resource the tool might assert. All are exact
   * strings: a rule that fails to match simply leaves the decision to the
   * user's configuration, which is the safe direction.
   */
  resources: string[]
}

function slash(value: string): string {
  return value.replaceAll("\\", "/")
}

function stringArg(args: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = args[key]
    if (typeof value === "string" && value.trim()) return value
  }
  return undefined
}

/**
 * The v2 tools derive a path resource as the workspace-relative canonical path
 * (or the canonical absolute path when the target sits outside the workspace).
 * A plugin cannot see the location root, so every plausible spelling is offered
 * and non-matching ones are inert.
 */
function pathResources(value: string, workspace: string): string[] {
  const absolute = isAbsolute(value) ? value : resolve(workspace, value)
  const workspaceRelative = relative(workspace, absolute)
  return [value, slash(value), slash(absolute), slash(workspaceRelative || ".")]
}

export function permissionTarget(
  tool: string,
  args: Record<string, unknown>,
  workspace: string,
): PermissionTarget | undefined {
  const action = TOOL_ACTIONS[tool]
  if (!action) return undefined

  if (tool === "bash" || tool === "shell") {
    const command = stringArg(args, "command")
    return command ? { action, resources: [command] } : undefined
  }

  if (tool === "apply_patch" || tool === "patch") {
    const patchText = typeof args.patchText === "string" ? args.patchText : ""
    const { paths, incomplete } = extractPatchPaths(patchText)
    if (incomplete || paths.length === 0) return undefined
    return { action, resources: paths.flatMap((path) => pathResources(path, workspace)) }
  }

  if (PATH_TOOLS.has(tool)) {
    const path = stringArg(args, "path", "filePath")
    return path ? { action, resources: pathResources(path, workspace) } : undefined
  }

  const literal = stringArg(args, "url", "query", "pattern", "name")
  return literal ? { action, resources: [literal] } : undefined
}

export function grantableResources(target: PermissionTarget): string[] {
  return [...new Set(target.resources)].filter((resource) => resource.length > 0 && !GLOB.test(resource))
}

type Entry = {
  rules: PermissionV2Rule[]
  expires: number
}

export type RuleStore = {
  /** Records a decision as rules the next permission evaluation will observe. */
  record(key: string, target: PermissionTarget, verdict: Verdict, now?: number): PermissionV2Rule[]
  /** Applies the base posture and all live decisions to an agent draft. */
  apply(draft: AgentDraft, now?: number): void
  /** Drops decisions whose lifetime has elapsed. Returns true if any were removed. */
  evict(now?: number): boolean
  size(): number
}

export type RuleStoreOptions = {
  /**
   * How long a recorded decision stays in the ruleset. It only has to outlive
   * the gap between the model emitting a tool call and the tool asserting its
   * permission, so this is deliberately short.
   */
  ttlMs: number
  /**
   * Rules applied underneath every decision. A catch-all deny must not use the
   * resource `*`: the tool registry drops any tool whose last matching rule is
   * an exact `*` deny, which would hide the tool from the model entirely.
   */
  base: PermissionV2Rule[]
  /** Agent ids to govern. Empty means every agent. */
  agents: Set<string>
}

export function makeRuleStore(options: RuleStoreOptions): RuleStore {
  const entries = new Map<string, Entry>()

  const evict = (now = Date.now()) => {
    let removed = false
    for (const [key, entry] of entries) {
      if (entry.expires > now) continue
      entries.delete(key)
      removed = true
    }
    return removed
  }

  const live = (now: number) => {
    evict(now)
    return [...entries.values()].flatMap((entry) => entry.rules)
  }

  return {
    record(key, target, verdict, now = Date.now()) {
      const rules = grantableResources(target).map(
        (resource): PermissionV2Rule => ({ action: target.action, resource, effect: verdict }),
      )
      if (rules.length === 0) return []
      entries.set(key, { rules, expires: now + options.ttlMs })
      return rules
    },
    apply(draft, now = Date.now()) {
      const additions = [...options.base, ...live(now)]
      if (additions.length === 0) return
      for (const agent of draft.list()) {
        if (options.agents.size > 0 && !options.agents.has(agent.id)) continue
        draft.update(agent.id, (item) => {
          item.permissions = [...item.permissions, ...additions]
        })
      }
    },
    evict,
    size: () => entries.size,
  }
}
