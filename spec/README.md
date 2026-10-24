# Sidged spec corpus

Machine-readable material for the draft standard. Status: draft, not for implementation. No certification program exists.

| Path | Contents |
|---|---|
| [schemas/](schemas/) | JSON Schema 2020-12 |
| [registries/](registries/) | Data classes, residency tags, intents, refusal reasons |
| [examples/](examples/) | Valid and invalid documents |
| [test-vectors/](test-vectors/) | Conformance vectors |
| [validate/](validate/) | Validator and tests |

```sh
pip install -r spec/validate/requirements.txt
python spec/validate/validate.py
python spec/validate/test_vectors.py --summary
python -m unittest discover -s spec/validate -v
```

Specification text in this repository is CC BY 4.0. This corpus and the validator are Apache-2.0. Provenance is recorded in [NOTICE](../NOTICE) and in the [migration note](../docs/analyse/02-SELFKIN-MIGRATION.md).
