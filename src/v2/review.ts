import type { LanguageModelV3 } from "@ai-sdk/provider"

import { parseDecision, truncate, withTimeout } from "../core.ts"

export type ReviewOutcome = {
  allowed: boolean
  reason: string
}

function responseText(content: ReadonlyArray<{ type: string; text?: string }>): string {
  return content
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text as string)
    .join("\n")
    .trim()
}

/**
 * Runs one reviewer turn against a language model. The v1 plugin delegated to a
 * hidden `auto-reviewer` subagent; v2 plugins cannot start sessions, so the
 * model is called directly. The prompt contract — a single `ALLOW: <reason>` or
 * `BLOCK: <reason>` line — is unchanged.
 */
export async function requestReview(
  model: LanguageModelV3,
  systemPrompt: string,
  request: string,
  timeoutMs: number,
): Promise<ReviewOutcome> {
  const result = await withTimeout(
    Promise.resolve(
      model.doGenerate({
        prompt: [
          { role: "system", content: systemPrompt },
          { role: "user", content: [{ type: "text", text: request }] },
        ],
        maxOutputTokens: 256,
        temperature: 0,
        abortSignal: AbortSignal.timeout(timeoutMs),
      }),
    ),
    timeoutMs,
    "LLM command review",
  )
  const text = responseText(result.content as ReadonlyArray<{ type: string; text?: string }>)
  if (!text) throw new Error("Reviewer returned an empty response")
  return parseDecision(text)
}

export function blockedToolMessage(reason: string): string {
  return `Blocked by auto mode: ${truncate(reason, 300)}`
}
