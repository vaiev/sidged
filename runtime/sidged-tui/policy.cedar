// Demo 1 owner policy (Cedar, 0002 R18) for sidged-tui.
// Permits exactly one call: egress.send to the Gemini OpenAI-compatible
// chat-completions URL (0007 R3 registry), for a User principal (the grant
// holder, `sub`), only for data class `query` and residency `unrestricted`.
// Anything else has no permit and is denied; a parse or evaluation error is
// a denial (0002). A deployment can pin the holder with --policy <file>
// (principal == User::"did:key:...").
permit (
  principal is User,
  action == Action::"egress.send",
  resource == Resource::"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
)
when {
  context.data_classes == ["query"] &&
  context.residency == ["unrestricted"]
};
