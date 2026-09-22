# HTTP-request
# T-Reqs Replication: HTTP Request Smuggling via Differential Fuzzing

A from-scratch, local-only replication of the core claim of:

> Bahruz Jabiyev, Steven Sprecher, Kaan Onarlioglu, Engin Kirda.
> **T-Reqs: HTTP Request Smuggling with Differential Fuzzing.** CCS 2021.

**Core claim being tested:** independent, individually-reasonable HTTP
processors (web servers / proxies) disagree on how to compute an HTTP
message body's length when Content-Length and Transfer-Encoding headers
are combined or malformed in specific ways, and this disagreement is
systematically discoverable via grammar-based differential fuzzing, and
is sufficient to smuggle a hidden request between them.

## What this does (and does not) do

- Implements **7 small rule-based parser models** (`src/parsers.py`) that
  encode the *documented* CL/TE preference behaviors reported by the
  paper for Apache, NGINX, Tomcat, ATS, HAProxy, Squid, and Varnish
  (Sections 5.2.2/5.2.3, Table 7/8). These are simplified stand-ins for
  the real server codebases, not the real servers.
- Implements a **grammar + mutation fuzzer** (`src/fuzzer.py`) that
  generates malformed CL/TE header combinations, mirroring the mutation
  categories in the paper (distorted header value, identity encoding,
  HTTP/1.0 + chunked, double Transfer-Encoding, chunk-size/data mismatch,
  manipulated chunk termination).
- Runs a **Stage-1-style differential test** (`src/experiment.py:run_stage1`)
  that finds which server pairs compute different body lengths for the
  same mutated input — this is the paper's central discovery mechanism.
- Runs a **Stage-3-style exploitability check** (`run_stage3`) that
  simulates whether a discrepancy is actually exploitable for smuggling
  (entrypoint forwards more bytes than the exitpoint consumes as body).
- **Does not** send any traffic to real servers or the internet, and does
  not include or reproduce the authors' original T-Reqs source code.
  All "servers" are pure Python functions running in-process.

This is intended as an educational / methodological replication (does the
*approach* reproduce the qualitative finding?), not a security tool.

## Repository layout

```
treqs-repro/
├── src/
│   ├── parsers.py      # 7 simplified server body-length models
│   ├── fuzzer.py        # grammar + mutation generator
│   ├── experiment.py    # Stage 1 (discrepancy) + Stage 3 (exploitability)
│   └── run_all.py       # runs everything, produces all figures
├── figures/              # generated PNGs (not checked in blank)
├── data/                 # generated summary.json
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 -m src.run_all
```

This will:
1. Run the Stage-1 differential-fuzzing experiment (default: 3000 mutated
   inputs per category x 6 categories = 18,000 inputs).
2. Save `figures/fig1_discrepancy_heatmap.png` — which entrypoint/exitpoint
   pairs disagree on body length (analogous to paper's Fig. 3/4).
3. Save `figures/fig2_success_rate_by_category.png` — fraction of mutated
   inputs per category that trigger a discrepancy (analogous to Table 5).
4. Run the Stage-3-style exploitability check and save
   `figures/fig3_exploitability.png`.
5. Run a mutation-budget sensitivity sweep (**extension beyond the
   original paper**) and save
   `figures/fig4_mutation_budget_sensitivity.png`.
6. Write `data/summary.json` with aggregate numbers.

Random seeds are fixed, so results are deterministic across runs.

## Key result summary (this replication)

- Out of 42 possible ordered server pairs (7 servers), **38** showed a
  body-length discrepancy under at least one mutation category — a large
  majority, consistent with the paper's headline finding that HRS-causing
  discrepancies are widespread across "individually secure" servers.
- `identity_encoding`, `v1_0_chunked`, `double_transfer_encoding`,
  `chunk_size_data_mismatch`, and `manipulated_chunk_termination` each
  produced discrepancies in >90% of mutated inputs; `distorted_header_value`
  was much rarer (~30%), matching the paper's qualitative note that many
  distorting mutations get normalized or rejected before reaching a
  vulnerable state.
- The Stage-3-style check confirms that most discrepancies found are
  directly exploitable for smuggling under the simple forwarded-vs-consumed
  byte-count model used here.

See the accompanying slide deck for full analysis, comparison to the
paper's reported numbers, and limitations.

## Limitations of this replication

- Only 7 of the paper's 10 technologies are modeled (the 3 CDNs — Akamai,
  Cloudflare, CloudFront — have no public source or version and are
  excluded, matching the paper's own "N/A" version entries for them).
- Server behaviors are hand-coded from the paper's *prose descriptions*
  of observed behavior, not from running the real software — so exact
  discrepancy counts are illustrative, not literal reproductions of the
  paper's Tables 2/5.
- The fuzzer covers only the entity-size-header (CL/TE) mutation space,
  not the full request-line and 67-header grammars used in the original
  T-Reqs (Listings 9-11), so absolute input/mutation counts are not
  comparable 1:1 with Table 2.
- The Stage-3 "exploitability" check uses a simplified byte-accounting
  model rather than actually running two servers behind a proxy on a
  persistent TCP connection as the paper does.
