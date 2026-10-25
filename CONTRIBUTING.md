# Contributing to Vaikor

Thank you for your interest. Vaikor is a pre-alpha research preview; the specifications in `docs/specs/` lead the code.

## Before you start

- Read [docs/vision/VISION.md](docs/vision/VISION.md) and the nine invariants in [README.md](README.md). A change that
  weakens an invariant is not accepted, however convenient.
- For anything larger than a fix, open an issue first and name the specification rule it implements or changes.

## Rules for changes

- **Developer Certificate of Origin:** every commit carries `Signed-off-by: Your Name <email>` (`git commit -s`),
  certifying the [DCO 1.1](https://developercertificate.org/).
- Code, comments, specifications and commit messages are in English.
- No hardcoded user phrases or keyword rules: intents, surfaces and capabilities are catalog- and schema-driven.
- Models propose, the Core decides: no path in which a model or a webview approves a consequential step.
- Training data holds no personal data, IP literals, credentials, or residency, approval and grant fields
  (`local-training/validate_dataset*.py` refuse them).

## AI-assisted contributions

Using AI coding assistants is fine; Vaikor itself is built with them (see
[How Vaikor Is Built](README.md#how-vaikor-is-built)). The rules stay the same:

- You understand every line you submit and can explain it in review. You ran the checks below yourself.
- Your `Signed-off-by` certifies the DCO for the whole change, including what an assistant drafted: you have the
  right to submit it under the project's licenses.
- Say in the pull request description when an assistant wrote a substantial part of the change.
- Never paste secrets, personal data or private chat content into a hosted assistant for work on Vaikor.

## Checks to run

```sh
cargo test  --manifest-path runtime/Cargo.toml --workspace --locked
cargo clippy --manifest-path runtime/Cargo.toml --workspace --all-targets -- -D warnings
cargo test  --manifest-path companion/Cargo.toml
python3 -I spec/validate/validate.py --quiet
python3 -I -m unittest discover -s local-training/tests -t local-training
bash scripts/tests/companion_ui_check.sh
```

## Licenses

Specifications and documentation: CC BY 4.0 ([LICENSE](LICENSE)). Code, schemas and the validator: Apache-2.0
([LICENSE-CODE](LICENSE-CODE)). By contributing you agree that your contribution is licensed the same way.
