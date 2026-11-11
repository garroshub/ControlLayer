# Developing

The released V0 uses deterministic authorization checks. An independent decision model has not demonstrated incremental value and is excluded from the release runtime and download.

The proposed extension places a decision model after a concrete task failure or ambiguous recovery choice and before the deterministic execution gate:

```text
Trusted task + proposed action + host-observed state
                        ↓
          Optional decision model
       recovery / escalation / abstain
                        ↓
       Deterministic authorization gate
                        ↓
       Execute or deny + effect audit
```

The host would treat model output as a recovery suggestion and check its authorization before execution. It cannot expand the user contract, override a denied policy, select a new destination or convert source instructions into trusted authority.

## Planned work

1. Build replayable decision inputs from real failed tasks, with explicit state and evidence provenance.
2. Compare judgment placement and narrow recovery options while retaining the same host authorization boundary. Uncertain outputs abstain.
3. Freeze new evaluation tasks and attack expressions before testing. Compare deterministic V0 against the same V0 plus the candidate model, with repeated runs and isolated warm-cost measurements.

The admission criteria concern independent semantic task recovery or actual cost reduction under matched safety gates. Classifier accuracy alone does not establish engineering value. If no independent increment is demonstrated, retain the deterministic implementation.

Decision-model integration requires an independent improvement over deterministic V0.
