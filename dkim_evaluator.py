import dkim
import re
from typing import Dict, List, Optional


DKIM_HEADER_RE = re.compile(
    rb"^DKIM-Signature:\s*(.+?)(?:\r\n(?!\s)|$)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

TAG_RE = re.compile(rb"([a-zA-Z]+)=([^;]+)")

ARC_SEAL_RE = re.compile(
    rb"^ARC-Seal:\s*(.+?)(?:\r\n(?!\s)|$)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

ARC_AUTH_RE = re.compile(
    rb"^ARC-Authentication-Results:\s*(.+?)(?:\r\n(?!\s)|$)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)


def _unfold_header(value: bytes) -> bytes:
    return re.sub(rb"\r\n\s+", b" ", value).strip()


def _parse_dkim_tags(header_value: bytes) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    header_value = _unfold_header(header_value)

    for k, v in TAG_RE.findall(header_value):
        tags[k.decode().lower()] = v.decode(errors="ignore").strip()

    return tags


def _extract_dkim_signatures(raw_email: bytes) -> List[Dict]:
    if isinstance(raw_email, str):
        raw_email = raw_email.encode(errors="ignore")

    headers_blob = raw_email.split(b"\r\n\r\n", 1)[0]
    signatures: List[Dict] = []

    for match in DKIM_HEADER_RE.finditer(headers_blob):
        raw_header = match.group(1)
        tags = _parse_dkim_tags(raw_header)

        if "d" not in tags or "s" not in tags:
            continue

        signatures.append({
            "domain": tags["d"].lower(),
            "selector": tags["s"],
            "algorithm": tags.get("a"),
            "canonicalization": tags.get("c"),
            "raw": raw_header,
        })

    return signatures


def _verify_dkim(raw_email: bytes) -> Dict:
    if isinstance(raw_email, str):
        raw_email = raw_email.encode(errors="ignore")

    try:
        valid = dkim.verify(raw_email)
        return {
            "dkim_present": True,
            "dkim_result": "PASS" if valid else "FAIL",
            "dkim_valid": valid,
        }

    except dkim.DKIMTemporaryError as e:
        return {
            "dkim_present": True,
            "dkim_result": "TEMPERROR",
            "dkim_valid": False,
            "error": str(e),
        }

    except dkim.DKIMException as e:
        return {
            "dkim_present": True,
            "dkim_result": "PERMERROR",
            "dkim_valid": False,
            "error": str(e),
        }


def _extract_arc_info(raw_email: bytes) -> Dict:
    if isinstance(raw_email, str):
        raw_email = raw_email.encode(errors="ignore")

    headers_blob = raw_email.split(b"\r\n\r\n", 1)[0]

    arc_seal = None
    arc_auth = None

    for line in headers_blob.split(b"\r\n"):
        if line.lower().startswith(b"arc-seal:"):
            arc_seal = line
        elif arc_seal and line.startswith(b" "):
            arc_seal += b"\r\n" + line
        elif arc_seal:
            break

    for line in headers_blob.split(b"\r\n"):
        if line.lower().startswith(b"arc-authentication-results:"):
            arc_auth = line
        elif arc_auth and line.startswith(b" "):
            arc_auth += b"\r\n" + line
        elif arc_auth:
            break

    if not arc_seal:
        return {"arc_present": False}

    arc_seal = _unfold_header(arc_seal).decode(errors="ignore")

    signer = None
    m = re.search(r"\bd=([^;\s]+)", arc_seal)
    if m:
        signer = m.group(1)

    arc_auth_value = None
    if arc_auth:
        arc_auth_value = _unfold_header(arc_auth).decode(errors="ignore")

    return {
        "arc_present": True,
        "arc_signer": signer,
        "arc_authentication_results": arc_auth_value,
        "arc_note": (
            "ARC indicates the message was authenticated by an upstream receiver. "
            "DKIM verification may fail locally due to header modifications. "
            "ARC is informational and not cryptographically re-verified."
        ),
    }


def _select_dkim_for_dmarc(
    signatures: List[Dict],
    header_from_domain: Optional[str],
) -> Optional[str]:

    if not signatures:
        return None

    if header_from_domain:
        header_from_domain = header_from_domain.lower()

        for sig in signatures:
            d = sig["domain"]
            if header_from_domain == d or header_from_domain.endswith("." + d):
                return d

    return signatures[0]["domain"]


def check_dkim(
    raw_email: bytes,
    header_from_domain: Optional[str] = None,
) -> Dict:

    verification = _verify_dkim(raw_email)
    signatures = _extract_dkim_signatures(raw_email)
    arc_info = _extract_arc_info(raw_email)

    dkim_domain = _select_dkim_for_dmarc(
        signatures,
        header_from_domain,
    )

    verification.update({
        "dkim_domain": dkim_domain,
        "dkim_aligned": False,
        "dkim_signatures_found": len(signatures),
        "dkim_signatures": signatures,
        "arc": arc_info,
    })

    return verification


def build_dkim_tree(
    dkim_result: Dict,
    header_from_domain: Optional[str],
) -> List[str]:

    tree = []
    tree.append("DKIM Verification")

    if not dkim_result.get("dkim_present"):
        tree.append(" ├─ DKIM-Signature present: NO")
        tree.append(" └─ DKIM RESULT → NONE")
        return tree

    tree.append(f" ├─ DKIM-Signatures found: {dkim_result['dkim_signatures_found']}")

    for idx, sig in enumerate(dkim_result.get("dkim_signatures", []), 1):
        tree.append(f" │  ├─ Signature #{idx}")
        tree.append(f" │  │  ├─ d = {sig['domain']}")
        tree.append(f" │  │  ├─ s = {sig['selector']}")
        tree.append(f" │  │  ├─ algorithm = {sig.get('algorithm')}")
        tree.append(f" │  │  └─ canonicalization = {sig.get('canonicalization')}")

    tree.append(" ├─ Cryptographic verification")
    tree.append(f" │  └─ Result → {dkim_result['dkim_result']}")

    arc = dkim_result.get("arc", {})
    if arc.get("arc_present"):
        tree.append(" ├─ ARC detected")
        tree.append(f" │  ├─ ARC signer → {arc.get('arc_signer')}")
        tree.append(" │  └─ Note → Message authenticated upstream (ARC is informational)")

    if header_from_domain:
        tree.append(f" ├─ Header-From domain = {header_from_domain}")
        tree.append(" ├─ DKIM domain selection for DMARC")

        if dkim_result.get("dkim_domain"):
            tree.append(f" │  └─ Selected DKIM domain → {dkim_result['dkim_domain']}")
        else:
            tree.append(" │  └─ No DKIM domain usable for DMARC")

    tree.append(f" └─ DKIM FINAL RESULT → {dkim_result['dkim_result']}")

    return tree
