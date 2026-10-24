permit(principal, action, resource)
when {
  context.audience == "did:example:ch-residency"
  && context.residency.contains("CH")
};
