# Delivery validation

The source distribution was independently extracted and installed as a non-editable wheel into a fresh Python 3.12 environment. Runtime dependencies passed `pip check`. All nine native regression checks passed. The import path was verified under the fresh environment site-packages.

All 302 historical model response tapes were replayed against the packaged runtime without inference. Native events, arguments, status, official scores and application states matched. Comparison normalizes observation timestamps and participant ordering. Per-episode results are recorded in `evidence/runtime-parity.json`. The replay uses stored model responses.

The self-contained demo passed all three comparison tabs in headless Edge, at desktop and mobile sizes, without JavaScript errors or mobile horizontal overflow. Figures were visually inspected and the README image/SVG audit passed. Quantitative data and plotting sources accompany the SVG, PNG and PDF figures.

A six-episode local actor smoke from the extracted package reproduced all three selected gains. V0 completed 3/3, while the baseline completed 0/3. All three candidate final application states exactly matched reviewed historical references. Five of six final states matched across both arms. The baseline summary task failed with a different trajectory and state. Model digest, Ollama version and loaded context were checked. The owned service was stopped and weights unloaded afterward. This selected smoke does not repeat the full safety benchmark. Its redacted receipt is `evidence/clean-environment-smoke.json`.

The archive uses an explicit source/evidence allowlist and SHA-256 inventory. It excludes caches, virtual environments, internal development tools, agent instructions, private raw captures, model weights and independent decision classifiers. Dependency and model notices are retained.

Machine-readable checks are in `evidence/delivery-checks.json`. The measurement report defines the original experiment and the six-episode smoke check.
