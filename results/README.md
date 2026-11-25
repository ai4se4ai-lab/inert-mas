# Result records

`final/` holds every result record of the study reported in the manuscript, archived read-only:
`final/<cluster>/<tag>/<model>/shard_<i>_of_<n>.jsonl`, one JSON object per run (182 files, 147,400 lines).

| Tag | Manifest (`hpc/manifests/`) | Content |
| --- | --- | --- |
| `final` | `final_zoo.yaml`, `final_zoo_large.yaml` | topology zoo: benign, attacked and ablation suites |
| `tamas` | `final_tamas.yaml` | TAMAS, all attack types and conditions |
| `tamas-split2` | `final_tamas_split2.yaml` | TAMAS DPI-split re-run after the provenance-split fix (`docs/open-questions.md`, item 12) |
| `tamas-scope` | `final_tamas_scope.yaml` | TAMAS with the post-hoc task-scope variant I2S |
| `seeds` | `final_seeds.yaml` | five seeds at temperature 0.7 |
| `adaptive` | `final_adaptive.yaml` | adaptive attacker, budget 10 |

Resumed shards repeat some rows, so the same shard can appear under two clusters. The analysis
de-duplicates by (case, model), which gives the 106,382 runs of the paper with no failed run
(`analysis/make_assets.py`, function `load`). Every record carries a `meta` object with the code
version, model digest, decoding configuration, manifest hash, shard, job and benchmark version.
SHA-256 checksums of all shards are in
`docs/paper/EMSE/replication-package/data/SHA256SUMS-results.txt`.

`push-check-20261123.jsonl` is a smoke check of the pipeline with the deterministic mock backend
(`backend: mock`, manifest `smoke`). It is not a result and no analysis reads it.

Regenerate every table, figure and number of the paper from these records with
`bash analysis/run_all.sh results/final`, or check them without changing anything with
`bash docs/paper/EMSE/replication-package/scripts/verify_all.sh`.
