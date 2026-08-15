import type { LanguageModelV3Prompt } from "@ai-sdk/provider"

import { projectConversation, type ConversationContext, type MessageWithParts, type ReviewContext } from "../core.ts"

/**
 * The v1 plugin rebuilt reviewer context by querying the session API. The v2
 * interception point is the language-model boundary, where the whole request —
 * system prompt, every user and assistant turn, and the tool calls already
 * made — is already in hand, so the context is read straight off the prompt.
 */
export function toMessages(prompt: LanguageModelV3Prompt): MessageWithParts[] {
  const messages: MessageWithParts[] = []
  for (const message of prompt) {
    if (message.role === "user") {
      const parts = message.content
        .filter((part) => part.type === "text")
        .map((part) => ({ type: "text", text: part.text }))
      if (parts.length) messages.push({ info: { role: "user" }, parts })
      continue
    }
    if (message.role !== "assistant") continue
    const parts: Array<Record<string, unknown>> = []
    for (const part of message.content) {
      if (part.type === "text") {
        parts.push({ type: "text", text: part.text })
        continue
      }
      if (part.type !== "tool-call") continue
      parts.push({
        type: "tool",
        tool: part.toolName,
        callID: part.toolCallId,
        state: { input: parseInput(part.input) },
      })
    }
    if (parts.length) messages.push({ info: { role: "assistant" }, parts })
  }
  return messages
}

export function parseInput(input: unknown): Record<string, unknown> {
  if (input && typeof input === "object") return input as Record<string, unknown>
  if (typeof input !== "string") return {}
  try {
    const parsed = JSON.parse(input)
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

export function conversationContext(prompt: LanguageModelV3Prompt, currentCallID?: string): ConversationContext {
  return projectConversation(toMessages(prompt), currentCallID)
}

/**
 * Git state and project documentation are not reachable from a v2 plugin
 * context, which exposes no location. The reviewer prompt keeps the fields so
 * its contract is unchanged; they are simply absent.
 */
export function reviewContext(prompt: LanguageModelV3Prompt, currentCallID?: string): ReviewContext {
  return { ...conversationContext(prompt, currentCallID), branch: null, gitStatus: null, projectDoc: null }
}
