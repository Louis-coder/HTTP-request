"""
Grammar-based differential fuzzer (simplified re-implementation of T-Reqs'
Stage 1: input generation + string/tree mutation, restricted to the
entity-size-header space: Content-Length / Transfer-Encoding).

This intentionally mirrors the CFG in Listing 10/11 of the paper but is a
compact, from-scratch reimplementation -- not the authors' code (which is
not included in this submission).
"""
import random
from dataclasses import replace
from .parsers import Request

CATEGORIES = [
    "well_formed",              # baseline valid CL/TE request (control)
    "distorted_header_value",   # stray chars in the TE header value
    "identity_encoding",        # TE: identity
    "v1_0_chunked",              # TE: chunked on HTTP/1.0
    "double_transfer_encoding",  # two TE headers (identity, chunked)
    "chunk_size_data_mismatch",  # chunk-size lies about chunk-data length
    "manipulated_chunk_termination",  # non-CRLF chunk terminator
]


def _base_request(version="1.1") -> Request:
    body = "4\r\nBBBB\r\n0\r\n\r\n"
    return Request(
        version=version,
        has_cl=True, cl_value=18,          # deliberately mismatched vs chunked len
        has_te=True, te_token="chunked", te_malformed=False,
        chunk_malformed=False,
        actual_chunk_bytes=len(body),
    )


def generate(category: str, rng: random.Random, mutation_budget: int = 2) -> Request:
    """Generate one mutated request belonging to `category`.
    mutation_budget caps how many independent mutations are combined,
    mirroring T-Reqs' "<= 2 mutations per input" design (Sec 4.2)."""
    req = _base_request()
    n_muts = rng.randint(1, mutation_budget)

    if category == "well_formed":
        return req

    if category == "distorted_header_value":
        # e.g. "Transfer-Encoding: ;chunked" or "chunked,"
        req = replace(req, te_malformed=True, te_token=rng.choice(
            [" ;chunked", "chunked,", "\tchunked"]))

    elif category == "identity_encoding":
        req = replace(req, te_token="identity")

    elif category == "v1_0_chunked":
        req = replace(req, version="1.0")

    elif category == "double_transfer_encoding":
        req = replace(req, te_token="identity,chunked", double_te=True)

    elif category == "chunk_size_data_mismatch":
        # claimed chunk size no longer matches actual bytes sent
        delta = rng.choice([-2, -1, 1, 2, 3])
        req = replace(req, chunk_malformed=True,
                      actual_chunk_bytes=req.actual_chunk_bytes + delta)

    elif category == "manipulated_chunk_termination":
        req = replace(req, chunk_malformed=True)

    # apply up to (n_muts - 1) extra "noise" mutations across secondary fields,
    # emulating T-Reqs combining multiple mutations per input
    for _ in range(n_muts - 1):
        knob = rng.choice(["cl_value", "chunk_extra"])
        if knob == "cl_value":
            req = replace(req, cl_value=req.cl_value + rng.choice([-4, -2, 2, 4]))
        else:
            req = replace(req, actual_chunk_bytes=req.actual_chunk_bytes + rng.choice([-1, 1]))

    return req
