import dns.resolver


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def fetch_spf(domain: str, trace=None) -> str | None:

    domain = normalize_domain(domain)
    if trace is not None:
        trace["steps"].append(f"TXT lookup for {domain}")

    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except Exception:
        return None

    spf_records = []

    for rdata in answers:
        parts = getattr(rdata, "strings", None)
        if parts is None:
            raw_parts = [str(rdata)]
        else:
            raw_parts = [
                part.decode() if isinstance(part, bytes) else part
                for part in parts
            ]

        for p in raw_parts:
            if any(ord(ch) < 32 and ch not in ("\t", "\r", "\n") for ch in p):
                return "PERMERROR: MALFORMED TXT"

        txt = "".join(raw_parts).replace('"', "").strip()

        if txt.lower().startswith("v=spf1"):
            spf_records.append(txt)

    if len(spf_records) > 1:
        return "PERMERROR: MULTIPLE SPF RECORDS"

    if not spf_records:
        return None

    return spf_records[0]


def parse_mechanisms(spf: str) -> list[str]:

    if not spf:
        return []
    if spf.startswith("PERMERROR"):
        return []
    return [t.strip() for t in spf.split()[1:] if t.strip()]


def build_spf_tree(domain: str, seen=None) -> dict:
    domain = normalize_domain(domain)

    if seen is None:
        seen = set()

    node = {
        "domain": domain,
        "spf": None,
        "mechanisms": [],
        "children": []
    }

    if domain in seen:
        node["mechanisms"].append("LOOP-DETECTED")
        return node

    seen.add(domain)

    spf = fetch_spf(domain)

    if spf is None:
        node["mechanisms"].append("NO-SPF")
        return node

    if spf.startswith("PERMERROR"):
        node["mechanisms"].append(spf)
        return node

    node["spf"] = spf
    mechanisms = parse_mechanisms(spf)

    for mech in mechanisms:
        node["mechanisms"].append(mech)

        if mech.startswith("redirect="):
            target = mech.split("=", 1)[1]
            node["children"].append(build_spf_tree(target, seen))

        elif mech.startswith("include:"):
            target = mech.split(":", 1)[1]
            node["children"].append(build_spf_tree(target, seen))

        else:
            continue

    return node


def print_tree(node: dict, indent: int = 0):
    prefix = " " * indent
    print(f"{prefix}{node['domain']}")

    if node.get("spf"):
        print(f"{prefix}  SPF: {node['spf']}")

    for mech in node["mechanisms"]:
        print(f"{prefix}   ├─ {mech}")

    for child in node["children"]:
        print_tree(child, indent + 6)


