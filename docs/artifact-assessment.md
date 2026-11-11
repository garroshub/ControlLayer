# Artifact assessment

This release uses a self-assessment checklist informed by ACM artifact-review criteria and NIST AI RMF measurement guidance. No ACM badge, NIST certification or external accreditation has been awarded.

| Reference criterion | Release evidence | Verification scope |
|---|---|---|
| ACM documented | README, runtime API example, reproduction commands and measurement definitions | Local documentation and link checks |
| ACM consistent | Per-episode metadata, source manifest and regenerated figure data | Recomputed totals and source hashes |
| ACM complete | Runtime, rule baseline, package metadata, tests, redacted results and figure scripts | Full raw historical conversations remain private |
| ACM exercisable | Fresh dependency installation, native simulator checks and a local model smoke run | Windows / Python 3.12 environment recorded in delivery checks |
| ACM verification evidence | Regression tests, recorded-response parity checks and executed package checks | Local author-side validation |
| NIST MEASURE 2.5 | Paired semantic completion, exact test result and generalization limits | Reused development benchmark and selected repetitions |
| NIST MEASURE 2.7 | Fixed attacks, delivered new probes and native-effect auditing | Stated simulator tools and authorization contracts |

The mapping uses published ACM conference artifact-evaluation criteria and the voluntary NIST AI RMF.

References accessed during release preparation on 2026-11-10

- [ACM artifact review policy](https://www.acm.org/publications/policies/artifact-review-and-badging-current)
- [ACM SIGSIM PADS 2024 artifact evaluation](https://sigsim.acm.org/conf/pads/2024/blog/artifact-evaluation/)
- [MODELS 2024 artifact-evaluation criteria](https://conf.researchr.org/track/models-2024/models-2024-artifact-evaluation)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

All figures have a data table, denominators, metric definitions and a regeneration script. They use untruncated zero-based bar axes and display the adverse cost result and official-score discrepancy. The measurement report states the uncertainty and coverage limits.
