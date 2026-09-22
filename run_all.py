import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.experiment import run_stage1, run_stage3
from src.parsers import SERVERS
from src.fuzzer import CATEGORIES

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "figures")
os.makedirs(OUT, exist_ok=True)
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA, exist_ok=True)

SERVER_NAMES = list(SERVERS.keys())


def fig_discrepancy_heatmap(stage1):
    """Reproduces the spirit of Figure 3 in the paper: which entrypoint/exitpoint
    pairs disagree on body length, aggregated across all header-related
    mutation categories."""
    n = len(SERVER_NAMES)
    mat = np.zeros((n, n))
    for cat, d in stage1["discrepancy_counts"].items():
        for (a, b), count in d.items():
            i, j = SERVER_NAMES.index(a), SERVER_NAMES.index(b)
            mat[i, j] += count

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(mat, cmap="Reds")
    ax.set_xticks(range(n)); ax.set_xticklabels(SERVER_NAMES, rotation=45, ha="right")
    ax.set_yticks(range(n)); ax.set_yticklabels(SERVER_NAMES)
    ax.set_xlabel("Entrypoint"); ax.set_ylabel("Exitpoint")
    ax.set_title("Reproduced: body-length discrepancies per server pair\n(all CL/TE mutation categories combined)")
    for i in range(n):
        for j in range(n):
            if mat[i, j] > 0:
                ax.text(j, i, int(mat[i, j]), ha="center", va="center", fontsize=7,
                        color="white" if mat[i, j] > mat.max() / 2 else "black")
    fig.colorbar(im, ax=ax, label="# discrepant inputs")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig1_discrepancy_heatmap.png"), dpi=150)
    plt.close(fig)
    return mat


def fig_success_rate_by_category(stage1):
    """Bar chart: fraction of mutated inputs per category that produced at
    least one discrepancy -- analogous to Table 5 (# successful / # inputs)."""
    cats = [c for c in CATEGORIES if c != "well_formed"]
    rates = [stage1["successful_inputs"][c] / stage1["total_inputs"][c] for c in cats]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(cats, rates, color="#c0392b")
    ax.set_ylabel("Fraction of mutated inputs causing a discrepancy")
    ax.set_title("Reproduced: discrepancy 'success rate' by mutation category")
    ax.set_xticklabels(cats, rotation=30, ha="right")
    for b, r in zip(bars, rates):
        ax.text(b.get_x() + b.get_width() / 2, r + 0.01, f"{r:.0%}", ha="center", fontsize=9)
    ax.set_ylim(0, 1.05)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig2_success_rate_by_category.png"), dpi=150)
    plt.close(fig)
    return dict(zip(cats, rates))


def fig_exploitability(stage3):
    """For each discrepant (entry, exit) pair, what fraction of trials are
    exploitable (entrypoint forwards more than exitpoint consumes) --
    analogous to the paper's Stage 3 HRS-potential verification (Fig 5/6)."""
    labels, rates = [], []
    for (cat, entry, exit_), r in stage3.items():
        if r["tested"] == 0:
            continue
        labels.append(f"{entry}->{exit_}\n({cat})")
        rates.append(r["exploitable"] / r["tested"])

    # keep only the top 15 for readability
    order = np.argsort(rates)[::-1][:15]
    labels = [labels[i] for i in order]
    rates = [rates[i] for i in order]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(range(len(labels)), rates, color="#2980b9")
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlabel("Fraction of trials exploitable for smuggling")
    ax.set_title("Reproduced Stage-3-style check: which discrepancies\nactually enable HRS (top 15 pairs/categories)")
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig3_exploitability.png"), dpi=150)
    plt.close(fig)


def fig_mutation_budget_sensitivity():
    """EXTENSION (goes beyond the paper): how does the discrepancy rate
    scale with the mutation budget (max mutations combined per input)?
    The paper fixes this at <=2 without an ablation; we sweep it."""
    budgets = [1, 2, 3, 4, 5]
    cats = [c for c in CATEGORIES if c != "well_formed"]
    rate_matrix = []
    for b in budgets:
        stage1 = run_stage1(n_per_category=800, mutation_budget=b, seed=42)
        rates = [stage1["successful_inputs"][c] / stage1["total_inputs"][c] for c in cats]
        rate_matrix.append(rates)
    rate_matrix = np.array(rate_matrix)

    fig, ax = plt.subplots(figsize=(8, 5))
    for i, cat in enumerate(cats):
        ax.plot(budgets, rate_matrix[:, i], marker="o", label=cat)
    ax.set_xlabel("Mutation budget (max mutations combined per input)")
    ax.set_ylabel("Discrepancy success rate")
    ax.set_title("Extension: sensitivity of discrepancy rate\nto mutation budget (not in original paper)")
    ax.legend(fontsize=7, loc="lower right")
    ax.set_xticks(budgets)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig4_mutation_budget_sensitivity.png"), dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    stage1 = run_stage1(n_per_category=3000, mutation_budget=2, seed=0)
    mat = fig_discrepancy_heatmap(stage1)
    rates = fig_success_rate_by_category(stage1)
    stage3 = run_stage3(stage1["discrepancy_counts"], n_trials=500, seed=1)
    fig_exploitability(stage3)
    fig_mutation_budget_sensitivity()

    summary = {
        "success_rate_by_category": rates,
        "total_discrepant_pairs_found": int((mat > 0).sum()),
        "total_server_pairs_possible": len(SERVER_NAMES) * (len(SERVER_NAMES) - 1),
    }
    with open(os.path.join(DATA, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
