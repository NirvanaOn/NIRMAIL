import dns.resolver
import hashlib
from typing import Dict, List, Optional
from publicsuffix2 import get_sld


_resolver = dns.resolver.Resolver()
_resolver.timeout = 2
_resolver.lifetime = 4


def fetch_dmarc_record(domain: str) -> Dict:
    tried = []
    records = []

    for target in (domain, get_org_domain(domain)):
        if target in tried:
            continue
        tried.append(target)

        try:
            answers = _resolver.resolve(f"_dmarc.{target}", "TXT")
            for rdata in answers:
                record = "".join(
                    p.decode() if isinstance(p, bytes) else p
                    for p in rdata.strings
                )
                if record.lower().startswith("v=dmarc1"):
                    records.append((target, record))
        except Exception:
            pass

    if len(records) == 0:
        return {"found": False}

    if len(records) > 1:
        return {
            "found": True,
            "error": "MULTIPLE_DMARC_RECORDS",
        }

    location, record = records[0]
    return {
        "found": True,
        "location": location,
        "record": record,
    }

def parse_dmarc_record(record: str) -> Dict:
    tags = {}

    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.lower()] = v.lower()

    return {
        "p": tags.get("p", "none"),
        "sp": tags.get("sp"),
        "aspf": tags.get("aspf", "r"),
        "adkim": tags.get("adkim", "r"),
        "pct": int(tags.get("pct", "100")),
    }



def get_org_domain(domain: str) -> str:
    return get_sld(domain) or domain


def is_aligned(
    auth_domain: Optional[str],
    from_domain: str,
    mode: str,
) -> bool:
    if not auth_domain:
        return False

    if mode == "s":
        return auth_domain == from_domain

    return get_org_domain(auth_domain) == get_org_domain(from_domain)


def pct_allows_enforcement(domain: str, pct: int) -> bool:
    h = hashlib.sha256(domain.encode()).hexdigest()
    bucket = int(h[:4], 16) % 100 + 1
    return bucket <= pct


def evaluate_dmarc(
    *,
    header_from_domain: str,
    spf_result: str,
    spf_domain: Optional[str],
    dkim_result: str,
    dkim_domain: Optional[str],
) -> Dict:

    lookup = fetch_dmarc_record(header_from_domain)

    if not lookup.get("found"):
        return {
            "dmarc_present": False,
            "dmarc_result": "NONE",
            "policy": "none",
            "enforcement": "ALLOW",
            "reason": "No DMARC record",
        }

    if "error" in lookup:
        return {
            "dmarc_present": True,
            "dmarc_result": "PERMERROR",
            "reason": lookup["error"],
            "enforcement": "ALLOW",
        }

    tags = parse_dmarc_record(lookup["record"])


    policy = tags["p"]
    if lookup["location"] != header_from_domain and tags["sp"]:
        policy = tags["sp"]

    spf_aligned = (
        spf_result == "PASS"
        and is_aligned(spf_domain, header_from_domain, tags["aspf"])
    )

    dkim_aligned = (
        dkim_result == "PASS"
        and is_aligned(dkim_domain, header_from_domain, tags["adkim"])
    )

    dmarc_pass = spf_aligned or dkim_aligned
    enforce = pct_allows_enforcement(header_from_domain, tags["pct"])

    if dmarc_pass:
        enforcement = "ALLOW"
    else:
        if not enforce:
            enforcement = "ALLOW (pct sampling)"
        else:
            enforcement = {
                "none": "ALLOW (monitoring)",
                "quarantine": "QUARANTINE",
                "reject": "REJECT",
            }.get(policy, "ALLOW")

    return {
        "dmarc_present": True,
        "dmarc_record": lookup["record"],
        "location": lookup["location"],
        "policy": policy,
        "aspf": tags["aspf"],
        "adkim": tags["adkim"],
        "pct": tags["pct"],
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "dmarc_result": "PASS" if dmarc_pass else "FAIL",
        "enforcement": enforcement,
    }


def build_dmarc_tree(dmarc: Dict) -> List[str]:
    tree = []
    tree.append("DMARC Evaluation")

    if not dmarc.get("dmarc_present"):
        tree.append(" ├─ DMARC record present: NO")
        tree.append(" └─ DMARC RESULT → NONE (policy not enforced)")
        return tree

    tree.append(f" ├─ DMARC record found at _dmarc")
    tree.append(f" │  ├─ policy (p) = {dmarc['policy']}")
    tree.append(f" │  ├─ aspf = {dmarc['aspf']}")
    tree.append(f" │  ├─ adkim = {dmarc['adkim']}")
    tree.append(f" │  └─ pct = {dmarc['pct']}")

    tree.append(" ├─ SPF alignment check")
    tree.append(
        f" │  └─ SPF aligned → {'PASS' if dmarc['spf_aligned'] else 'FAIL'}"
    )

    tree.append(" ├─ DKIM alignment check")
    tree.append(
        f" │  └─ DKIM aligned → {'PASS' if dmarc['dkim_aligned'] else 'FAIL'}"
    )

    tree.append(" ├─ DMARC policy evaluation")
    tree.append(
        f" │  └─ SPF OR DKIM aligned → {dmarc['dmarc_result']}"
    )

    tree.append(" ├─ Policy enforcement decision")
    tree.append(f" │  └─ Enforcement → {dmarc['enforcement']}")

    tree.append(f" └─ DMARC FINAL RESULT → {dmarc['dmarc_result']}")

    return tree
