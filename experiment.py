"""
Differential-fuzzing experiment driver.

Stage 1 (find discrepancies): for every mutated request, ask every server
model for its computed body length. Any pair of servers that disagree is
a "discrepancy" for that input -- this directly mirrors Section 5.1 of
the paper ("mismatches between parsed message body lengths").

Stage 3-like check (HRS verification): for a discrepant pair (entrypoint,
exitpoint), simulate what the entrypoint forwards (its own computed body
length worth of bytes from the on-the-wire request) and what the exitpoint
consumes as "this request's body" from that forwarded stream. If the
exitpoint consumes fewer bytes than the entrypoint forwarded, the leftover
bytes would be glued to the *next* request on the connection -> smuggling
succeeds (mirrors Listing 12-14 in the paper). This is a local, purely
in-memory simulation; no network requests are made to any real host.
"""
import random
from collections import defaultdict
from itertools import permutations

from .parsers import SERVERS
from .fuzzer import CATEGORIES, generate


def run_stage1(n_per_category: int = 2000, mutation_budget: int = 2, seed: int = 0):
    rng = random.Random(seed)
    server_names = list(SERVERS.keys())

    # discrepancy_counts[category][(entry, exit)] = count
    discrepancy_counts = defaultdict(lambda: defaultdict(int))
    successful_inputs = defaultdict(int)   # per category: mutation sets that caused >=1 discrepancy
    total_inputs = defaultdict(int)

    for cat in CATEGORIES:
        for _ in range(n_per_category):
            req = generate(cat, rng, mutation_budget=mutation_budget)
            total_inputs[cat] += 1
            lengths = {name: fn(req) for name, fn in SERVERS.items()}
            caused_discrepancy = False
            for a, b in permutations(server_names, 2):
                if lengths[a] != lengths[b]:
                    discrepancy_counts[cat][(a, b)] += 1
                    caused_discrepancy = True
            if caused_discrepancy and cat != "well_formed":
                successful_inputs[cat] += 1

    return {
        "discrepancy_counts": discrepancy_counts,
        "successful_inputs": successful_inputs,
        "total_inputs": total_inputs,
    }


def run_stage3(discrepancy_counts, n_trials: int = 500, seed: int = 1):
    """For every (category, entry, exit) pair that showed a discrepancy in
    Stage 1, sample fresh mutated requests and check whether the
    discrepancy is *exploitable*: entrypoint forwards more bytes than the
    exitpoint consumes as body, leaving a residue that would desynchronize
    the connection (HRS)."""
    rng = random.Random(seed)
    results = defaultdict(lambda: {"tested": 0, "exploitable": 0})

    for cat in CATEGORIES:
        if cat == "well_formed":
            continue
        pairs = list(discrepancy_counts[cat].keys())
        for (entry, exit_) in pairs:
            entry_fn = SERVERS[entry]
            exit_fn = SERVERS[exit_]
            for _ in range(n_trials):
                req = generate(cat, rng, mutation_budget=2)
                entry_len = entry_fn(req)
                exit_len = exit_fn(req)
                results[(cat, entry, exit_)]["tested"] += 1
                # Exploitable when entrypoint forwards MORE bytes as part
                # of this request than the exitpoint consumes as body --
                # i.e. exitpoint leaves a residue that glues onto the next
                # request on the connection.
                if entry_len > exit_len:
                    results[(cat, entry, exit_)]["exploitable"] += 1

    return results
