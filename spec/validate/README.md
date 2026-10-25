# Vaikor Validator

> **Status: Draft, not for implementation.** Licensed under Apache-2.0 ([LICENSE-CODE](../../LICENSE-CODE)).

Checks JSON documents against the v0.1 schemas in [../schemas](../schemas) in two layers: JSON Schema 2020-12, then semantic checks that JSON Schema cannot express (for example that a delegated capability token only narrows its parent, or that a session record links a privacy report to every egress and carries a tier display signed by the Core key). It does not check signatures, key trust, revocation, replay, or clocks.

```sh
pip install -r spec/validate/requirements.txt
python spec/validate/validate.py                          # all examples, with expected results
python spec/validate/validate.py doc.json --schema envelope
python -m unittest discover -s spec/validate -v           # tests
```

The tests check that every schema is valid JSON Schema 2020-12 with the required `$id`, `title`, and `description`; that every valid example passes and every `*.invalid.json` example fails; that every schema has both kinds of example; that every invalid example is explained in [examples/README.md](../examples/README.md); and that no em-dashes or en-dashes are used.

`test_vectors.py` runs the shared [test vectors](../test-vectors/README.md): it checks every vector file against `vector.schema.json` and the refusal-reason registry, and runs the static operations against the validator. Normative vectors must pass; provisional ones are only reported. `python spec/validate/test_vectors.py --summary` prints a per-file summary.

## Checking a published copy

A site that serves the spec (vaikor.com/spec/) checks its copy against a pinned commit:

```sh
python spec/validate/check_published.py <dir-with-schemas-and-registries>
```

It passes only when the copy is that commit's spec byte for byte, every `$id` is `https://vaikor.com/spec/schemas/<name>.schema.json`, every `$ref` resolves within the copy without network access, and every example validates against the copy as it does against the repository. `test_published.py` covers a changed byte, a missing or extra file, a wrong `$id`, an unresolvable `$ref` and a missing directory.

## Continuous Integration

[.github/workflows/validate.yml](../../.github/workflows/validate.yml) is the GitHub Actions workflow that runs the validator and the tests on every push and pull request.

The unittest module also checks `jcs-signing-input`, `sign`, `verify`, and `ed25519-sign` with `rfc8785` and `cryptography`. `validate.py` itself still does not verify signatures.
