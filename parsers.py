"""
Simplified parser models for T-Reqs replication.

These are NOT real server implementations. They are small rule-based models
that encode the documented CL/TE preference behaviors reported in
Jabiyev et al., "T-Reqs: HTTP Request Smuggling with Differential Fuzzing"
(CCS 2021), Sections 5.2.2 and 5.2.3 and Table 7/8.

The goal is to reproduce the *systematic differential-fuzzing methodology*
(compare how independent HTTP processors decide message body boundaries),
not to build (or attack) real servers. Nothing here sends traffic to any
external host -- all "servers" are local Python functions.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Request:
    version: str            # "1.0" or "1.1"
    has_cl: bool
    cl_value: int            # declared Content-Length
    has_te: bool
    te_token: str             # "chunked", "identity", "chunked,identity", or malformed variant
    te_malformed: bool        # header value has stray chars, e.g. ";chunked" or "chunked "
    chunk_malformed: bool     # body-level malformation (bad terminator, size/data mismatch)
    actual_chunk_bytes: int   # true encoded length if TE is honored and body walked correctly
    double_te: bool = False   # two Transfer-Encoding headers present


# --- helper -----------------------------------------------------------
def _te_is_chunked(req: Request) -> bool:
    """True if the *last* declared TE token is (something recognizable as) chunked."""
    if not req.has_te:
        return False
    token = req.te_token.split(",")[-1].strip()
    return token.startswith("chunked")


def _computed_te_length(req: Request) -> int:
    """Body length a parser gets if it honors TE and walks the chunk stream,
    even if it tolerates minor malformations."""
    return req.actual_chunk_bytes


# --- individual server models ------------------------------------------
# Each returns the body length (int) the server would forward/consume,
# or -1 to mean "server rejects the request" (400/close), which we treat
# as its own outcome for discrepancy purposes.

def apache(req: Request) -> int:
    # RFC-strict-ish: honors well-formed TE:chunked over CL. A malformed TE
    # header value (e.g. containing a stray token/semicolon) is not
    # recognized as chunked, so Apache falls back to CL if present.
    if req.has_te and not req.te_malformed and _te_is_chunked(req):
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


def nginx(req: Request) -> int:
    # NGINX is lenient about body-level chunk malformations (e.g. accepts
    # LF where CRLF is expected) but still requires a syntactically valid
    # TE header value to recognize chunked mode.
    if req.has_te and not req.te_malformed and _te_is_chunked(req):
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


def tomcat(req: Request) -> int:
    # Tomcat does not support chunked encoding on HTTP/1.0 -> falls back to
    # CL. On HTTP/1.1 it generally prefers CL whenever both are present
    # (paper: "all servers prefer [TE], whereas Tomcat prefers [CL]").
    if req.version == "1.0":
        return req.cl_value if req.has_cl else 0
    if req.has_cl:
        return req.cl_value
    if req.has_te and _te_is_chunked(req):
        return _computed_te_length(req)
    return 0


def ats(req: Request) -> int:
    # Apache Traffic Server: ignores the body entirely when TE value is
    # "identity" (paper 5.2.2). Otherwise lenient TE parsing (tolerates
    # many request-line/header malformations), else falls back to CL.
    if req.has_te and req.te_token.strip() == "identity":
        return 0
    if req.has_te and _te_is_chunked(req):
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


def haproxy(req: Request) -> int:
    # HAProxy supports chunked encoding even on HTTP/1.0 (unlike Tomcat),
    # and generally prefers TE over CL when both present.
    if req.has_te and _te_is_chunked(req):
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


def squid(req: Request) -> int:
    # Squid ignores the body when TE:identity is declared, same category
    # as ATS. Also stricter about chunk-body malformation -> falls back
    # to CL if the chunk stream itself is malformed.
    if req.has_te and req.te_token.strip() == "identity":
        return 0
    if req.has_te and _te_is_chunked(req) and not req.chunk_malformed:
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


def varnish(req: Request) -> int:
    # Varnish "cleans" the connection: it still prefers TE if chunked is
    # parseable, else CL. It never leaves stray bytes if it ignores a
    # body (relevant only for HRS follow-up, not raw body length).
    if req.has_te and _te_is_chunked(req):
        return _computed_te_length(req)
    if req.has_cl:
        return req.cl_value
    return 0


SERVERS = {
    "Apache": apache,
    "NGINX": nginx,
    "Tomcat": tomcat,
    "ATS": ats,
    "HAProxy": haproxy,
    "Squid": squid,
    "Varnish": varnish,
}
