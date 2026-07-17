# Fuzz Regression Corpus

Minimized crash artifacts from fuzz testing. These files are kept as
regression tests to ensure previously discovered bugs are not reintroduced.

Each file is a minimized input that triggered a panic or incorrect behavior
during fuzzing. The filename hash identifies the specific crash; the original
full-size input is in `fuzz/artifacts/`.

To reproduce a crash:

```bash
cargo fuzz run <target> fuzz/regression/<crash-file>
```
