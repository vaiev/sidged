# Registry: Data Classes

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

Data classes label personal data for egress policy, residency, redaction, and reporting (Sidged L7). A data class is a registered top-level class, optionally followed by dot-separated subclasses (`location.precise`, `contacts.email`). Subclasses need no registration; the ones listed below are recommended so that runtimes agree. Classes not in this registry start with `x-`.

A message, manifest, or report lists every class its content contains. A subclass is covered by its top-level class: a policy on `contacts` applies to `contacts.email`.

The **suggested default** column is non-normative. It is what a runtime SHOULD propose at onboarding (Sidged L5) for the "sensitive" and "relay-required" policy marks used in Sidged L7; the owner decides.

| Class | Meaning | Recommended subclasses | Suggested default |
|---|---|---|---|
| `identity` | Who the user is: names, identifiers, addresses, account names | `identity.name`, `identity.address`, `identity.government-id` | sensitive |
| `contacts` | Data about other people the user knows | `contacts.name`, `contacts.email`, `contacts.phone` | sensitive |
| `communications` | Content and metadata of messages, emails, and calls | `communications.content`, `communications.metadata` | sensitive, relay-required |
| `calendar` | Events and availability | `calendar.events`, `calendar.availability` | normal |
| `location` | Where the user or a device is or was | `location.precise`, `location.coarse`, `location.history` | sensitive, relay-required |
| `health` | Physical or mental health, including wellbeing data | `health.records`, `health.fitness` | sensitive, relay-required, local-only proposed |
| `biometric` | Face, voice, fingerprint, and other biometric data | `biometric.template`, `biometric.voice` | sensitive, local-only proposed |
| `finance` | Accounts, payments, transactions, income | `finance.transactions`, `finance.account` | sensitive, relay-required |
| `documents` | Files and their text | `documents.text`, `documents.metadata` | normal |
| `media` | Photos, audio, video | `media.photo`, `media.audio`, `media.video` | sensitive |
| `home` | Home and IoT sensor and state data | `home.sensor`, `home.presence` | normal; `home.presence` sensitive |
| `device` | Device telemetry and configuration | `device.telemetry`, `device.config` | normal |
| `query` | Text written for one call (prompts, searches) without other classes | `query.general` | normal |
| `usage` | Activity, app usage, and behaviour patterns | `usage.activity`, `usage.history` | sensitive |
| `adaptation` | Adaptation Profile settings and derived style instructions (Sidged L5) | | sensitive, local-only proposed |
| `memory` | Stored agent memory (Sidged L5) | `memory.facts`, `memory.episodes` | sensitive |
| `secrets` | Credentials, keys, tokens, one-time codes | | never leaves the device (Sidged L2) |
