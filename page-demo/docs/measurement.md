# Evaluation methodology

The recorded comparison contains 97 normal tasks and 54 fixed attack episodes per arm. The baseline is the frozen R2 rules implementation. Both arms use Qwen3.5 4B Q4_K_M and the same original AgentDojo tool catalog and scorer.

## Utility

Official task completions are 44/97 and 47/97. Task-paired review identifies three semantic gains and zero semantic losses. The gains are explicit webpage reading, a source-bound invitation using the exact requested identity, and publication of the requested source summary to the requested channel.

There are 24 reviewed equal-outcome pairs and 70 pairs with strictly identical complete observed behavior. Equality establishes zero paired difference. It does not label every equal pair successful.

The exact two-sided McNemar calculation for three gains and zero losses gives p = 0.25. The exact test provides limited evidence about improvement beyond these tasks. The benchmark was reused during development. Selected candidate tasks were repeated, and eight additional negative expressions were frozen before their execution.

## Security

The original official attack scores remain 0/54 for the baseline and 1/54 for V0. The flagged scorer reconstructs attack progress from proposed function names and arguments, including rejected calls. Its current episode contains four blocked operations and only two native reads. Slack state is unchanged. The strict original official-score criterion remains failed.

Execution auditing covers all 108 attacked captures and finds zero non-read native calls. Ten V0 episodes append the requested webpage to a read log. This execution-based engineering gate was fixed before the final run and is reported alongside the official scores.

The 54 fixed episodes span 27 scenarios in two styles. They share mechanisms. The coverage is limited to these attack mechanisms. Baseline exposure is lower because it rejects some legitimate source reads. Eight new candidate probes were delivered to the actor and produced no unauthorized native effect within the declared contracts.

Summary contracts accept ordered original source sentences. A source instruction can appear as quoted summary content at the user-authorized destination. HTTP redirect handling and transport-level destination restrictions are not implemented. General paraphrased summaries, downstream interpretation of quoted instructions, read minimization, answer privacy and real external email delivery are outside the verified scope.

## Cost

151 pairs have complete warm observations. Total wall time is 3170.53 seconds for the baseline and 3241.98 seconds for V0, an increase of approximately 2.25%. Wall time includes per-episode process and observer overhead. The observed improvement concerns task completion. Runtime cost increased.

## Source evidence

`evidence/final.json` contains allowlisted per-episode scores, costs, review verdicts and hashes. `evidence/attack-execution.json` contains redacted native-call summaries. `evidence/scoring-adjudication.json` identifies the flagged case and its execution review.

Full original model conversations and simulator states are retained privately. Public hashes support provenance and new reproduction runs. A public hash alone cannot independently validate the contents of a private state. New local reproduction writes its own complete audit evidence under the selected output directory.

The runtime contains deterministic checks and a local acting model interface. The experimental independent decision classifiers were removed after zero model-judge participation and no demonstrated independent benefit.

## Related implementations

Execution-time tool policies and provenance checks have established precedents. Mechanism comparisons were inspected at pinned revisions of [Progent](https://github.com/lindsey98/progent/tree/769370d4d38419ee7c26b08e7eddf2572985bf18), [CaMeL](https://github.com/google-research/camel-prompt-injection/tree/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8) and [Fides](https://github.com/microsoft/fides/tree/669c046c4adbc56ee49c9672fdd30c54937ea062).

The experiments measure task recovery against the R2 baseline. The cited projects provide mechanism comparisons.
