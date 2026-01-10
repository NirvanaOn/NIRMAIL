import re
import ipaddress
import dns.resolver
import dns.reversename
import time
from typing import Dict, List, Optional, Set, Tuple

from spf_extractor import fetch_spf, parse_mechanisms, normalize_domain

MAX_SPF_LOOKUPS = 10
MAX_RECURSION_DEPTH = 20


def cached_resolve(domain: str, rtype: str, trace: Optional[Dict], dns_cache: Dict[Tuple[str, str], List]) -> List:
    key = (rtype, domain)
    if key in dns_cache:
        if trace:
            trace["steps"].append(f"DNS cache hit: {rtype} {domain}")
        return dns_cache[key]

    if trace:
        trace["steps"].append(f"DNS lookup: {rtype} {domain}")

    try:
        answers = dns.resolver.resolve(domain, rtype)
    except Exception:
        try:
            answers = dns.resolver.resolve(domain, rtype, tcp=True)
            if trace:
                trace["steps"].append(f"DNS lookup (TCP fallback): {rtype} {domain}")
        except Exception:
            answers = []

    dns_cache[key] = list(answers)
    return dns_cache[key]



def log(trace: Optional[Dict], msg: str) -> None:
    if trace is not None:
        trace["steps"].append(msg)


def split_qualifier(mech: str) -> Tuple[str, str]:
    if mech and mech[0] in "+-~?":
        return mech[0], mech[1:]
    return "+", mech


def result_from_qualifier(q: str) -> str:
    return {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}.get(q, "NEUTRAL")


def resolve_a_aaaa(domain: str, trace: Optional[Dict], dns_cache: Dict) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    ips = []
    for r in cached_resolve(domain, "A", trace, dns_cache):
        try:
            ips.append(ipaddress.ip_address(r.to_text()))
        except Exception:
            pass
    for r in cached_resolve(domain, "AAAA", trace, dns_cache):
        try:
            ips.append(ipaddress.ip_address(r.to_text()))
        except Exception:
            pass
    return ips


def resolve_mx(domain: str, trace: Optional[Dict], dns_cache: Dict) -> List[str]:
    hosts = []
    for r in cached_resolve(domain, "MX", trace, dns_cache):
        try:
            hosts.append(str(r.exchange).rstrip("."))
        except Exception:
            pass
    return hosts


def resolve_ptr(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, trace: Optional[Dict], dns_cache: Dict) -> List[str]:
    names = []
    try:
        rev_name = dns.reversename.from_address(str(ip_obj))
        for r in cached_resolve(str(rev_name), "PTR", trace, dns_cache):
            try:
                names.append(str(r.target).rstrip("."))
            except Exception:
                pass
    except Exception:
        pass
    return names


def ip_matches(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, cidr: Optional[int], ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        if cidr is not None:
            length = cidr
        else:
            length = 32 if addr.version == 4 else 128
        net = ipaddress.ip_network(f"{addr}/{length}", strict=False)
        return ip_obj in net
    except Exception:
        return False


def check_exists(domain: str, trace: Optional[Dict], dns_cache: Dict) -> bool:
    log(trace, f"EXISTS check: {domain}")
    return len(resolve_a_aaaa(domain, trace, dns_cache)) > 0


def _split_mail_from(mail_from: Optional[str]) -> Tuple[str, str]:
    if not mail_from or mail_from == "<>":
        return "", ""
    mf = mail_from.strip("<>")
    if "@" in mf:
        local, dom = mf.split("@", 1)
        return local, normalize_domain(dom)
    return mf, ""


def expand_macros(
    template: str,
    ip: str,
    domain: str,
    mail_from: Optional[str] = None,
    helo: Optional[str] = None,
) -> str:
    if not template:
        return template

    local_part, sender_domain = _split_mail_from(mail_from)
    domain = normalize_domain(domain)
    helo = helo or ""
    ip_str = ip

    def value(letter: str) -> str:
        letter = letter.lower()
        mapping = {
            "s": mail_from or "",
            "l": local_part,
            "o": sender_domain,
            "d": domain,
            "i": ip_str,
            "h": helo,
            "c": ip_str,
            "r": domain,
            "t": str(int(time.time())),
            "v": "in-addr" if ipaddress.ip_address(ip_str).version == 4 else "ip6",
        }
        return mapping.get(letter, "")

    out = []
    i = 0
    while i < len(template):
        if template[i] != "%":
            out.append(template[i])
            i += 1
            continue

        if i + 1 < len(template):
            next_char = template[i + 1]
            if next_char in "%_-":
                out.append({"%": "%", "_": " ", "-": "-"}[next_char])
                i += 2
                continue
            if next_char == "{":
                end = template.find("}", i + 2)
                if end == -1:
                    i += 1
                    continue
                inner = template[i + 2 : end]
                i = end + 1

                m = re.match(r"([A-Za-z])(\d+)?(r)?(.*)", inner)
                if not m:
                    continue
                letter, num_str, reverse, delims = m.groups()
                raw = value(letter)
                delims = delims or ("." if letter.lower() != "i" else ("." if ipaddress.ip_address(ip_str).version == 4 else ":"))
                parts = re.split(f"[{re.escape(delims)}]+", raw) if raw else []
                if num_str:
                    try:
                        n = int(num_str)
                        parts = parts[-n:]
                    except ValueError:
                        pass
                if reverse:
                    parts.reverse()
                out.append(".".join(p for p in parts if p))
                continue

            out.append(value(next_char))
            i += 2
            continue

        i += 1

    return "".join(out)



def _parse_mechanism_target(
    mech: str,
    prefix: str,
    default_domain: str,
    ip: str,
    mail_from: Optional[str],
    helo: Optional[str],
) -> Tuple[str, Optional[int]]:
    body = mech[len(prefix) :]
    target = default_domain
    cidr: Optional[int] = None

    if body.startswith(":"):
        rest = body[1:]
        if "/" in rest:
            domain_part, cidr_part = rest.split("/", 1)
            expanded = expand_macros(domain_part, ip, default_domain, mail_from, helo)
            target = normalize_domain(expanded) if expanded else default_domain
            try:
                cidr = int(cidr_part)
            except ValueError:
                cidr = None
        else:
            expanded = expand_macros(rest, ip, default_domain, mail_from, helo)
            target = normalize_domain(expanded) if expanded else default_domain
    elif body.startswith("/"):
        try:
            cidr = int(body[1:])
        except ValueError:
            pass

    return target, cidr


def evaluate_spf(
    domain: str,
    ip: str,
    state: Optional[Dict] = None,
    trace: Optional[Dict] = None,
    depth: int = 0,
    mail_from: Optional[str] = None,
    helo: Optional[str] = None,
) -> str:
    if trace is None:
        trace = {"steps": [], "lookups": 0}
    if state is None:
        state = {
            "seen": set(),
            "spf_lookups": 0,
            "dns_cache": {},
        }

    if depth > MAX_RECURSION_DEPTH:
        return "PERMERROR (recursion depth exceeded)"

    domain = normalize_domain(domain)
    if domain in state["seen"]:
        return "PERMERROR (DNS loop detected)"

    state["seen"].add(domain)
    log(trace, f"Evaluating SPF for domain: {domain}")

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "PERMERROR (invalid IP address)"

    spf_record = fetch_spf(domain, trace)
    if not spf_record:
        return "NONE"
    if spf_record.startswith("PERMERROR"):
        return spf_record

    log(trace, f"SPF record: {spf_record}")
    mechanisms = parse_mechanisms(spf_record)

    redirect_target: Optional[str] = None
    exp_domain: Optional[str] = None
    matched = False

    for raw_mech in mechanisms:
        if matched:
            break

        qualifier, mech = split_qualifier(raw_mech)
        log(trace, f"Checking mechanism: {raw_mech}")

        # exp=
        if mech.startswith("exp="):
            expanded = expand_macros(mech[len("exp=") :], ip, domain, mail_from, helo)
            exp_domain = normalize_domain(expanded)
            continue

        # redirect=
        if mech.startswith("redirect="):
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"
            expanded = expand_macros(mech[len("redirect=") :], ip, domain, mail_from, helo)
            redirect_target = normalize_domain(expanded)
            continue

        # ip4:/ip6:
        if mech.startswith(("ip4:", "ip6:")):
            try:
                net = ipaddress.ip_network(mech.split(":", 1)[1], strict=False)
                if ip_obj in net:
                    matched = True
                    return result_from_qualifier(qualifier)
            except Exception:
                return "PERMERROR (invalid ip mechanism)"
            continue

        # include:
        if mech.startswith("include:"):
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"

            expanded = expand_macros(mech[len("include:") :], ip, domain, mail_from, helo)
            target = normalize_domain(expanded)
            result = evaluate_spf(target, ip, state, trace, depth + 1, mail_from, helo)

            if result == "PASS":
                matched = True
                return result_from_qualifier(qualifier)
            if result.startswith("PERMERROR") or result.startswith("TEMPEROR"):
                return result  # Propagate hard errors
            continue

        # a
        if mech == "a" or mech.startswith(("a:", "a/")):
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"
            target, cidr = _parse_mechanism_target(mech, "a", domain, ip, mail_from, helo)
            for addr in resolve_a_aaaa(target, trace, state["dns_cache"]):
                if ip_matches(addr, cidr, ip_obj):
                    matched = True
                    return result_from_qualifier(qualifier)
            continue

        # mx
        if mech == "mx" or mech.startswith(("mx:", "mx/")):
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"
            target, cidr = _parse_mechanism_target(mech, "mx", domain, ip, mail_from, helo)
            for mx_host in resolve_mx(target, trace, state["dns_cache"]):
                for addr in resolve_a_aaaa(mx_host, trace, state["dns_cache"]):
                    if ip_matches(addr, cidr, ip_obj):
                        matched = True
                        return result_from_qualifier(qualifier)
            continue

        # exists:
        if mech.startswith("exists:"):
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"
            expanded = expand_macros(mech[len("exists:") :], ip, domain, mail_from, helo)
            target = normalize_domain(expanded)
            if check_exists(target, trace, state["dns_cache"]):
                matched = True
                return result_from_qualifier(qualifier)
            continue

        # ptr (deprecated)
        if mech.startswith("ptr"):
            log(trace, "Warning: ptr mechanism is deprecated")
            state["spf_lookups"] += 1
            trace["lookups"] = state["spf_lookups"]
            if state["spf_lookups"] > MAX_SPF_LOOKUPS:
                return "PERMERROR (too many DNS lookups)"
            target_domain = domain
            if ":" in mech:
                expanded = expand_macros(mech.split(":", 1)[1], ip, domain, mail_from, helo)
                target_domain = normalize_domain(expanded)
            ptr_names = resolve_ptr(ip_obj, trace, state["dns_cache"])
            for name in ptr_names:
                if target_domain and not name.endswith("." + target_domain) and name != target_domain:
                    continue

                if any(addr == ip_obj for addr in resolve_a_aaaa(name, trace, state["dns_cache"])):
                    matched = True
                    return result_from_qualifier(qualifier)
            continue

        # all
        if mech == "all":
            matched = True
            result = result_from_qualifier(qualifier)
            if result == "FAIL" and exp_domain:
                exp_txt = fetch_spf(exp_domain, trace)
                if exp_txt and not exp_txt.startswith("PERMERROR"):
                    explanation = expand_macros(exp_txt, ip, domain, mail_from, helo)
                    log(trace, f"Explanation: {explanation}")
            return result

        log(trace, f"Unknown mechanism ignored: {mech}")


    if redirect_target and not matched:
        log(trace, f"Redirecting to: {redirect_target}")
        return evaluate_spf(redirect_target, ip, state, trace, depth + 1, mail_from, helo)

    return "NEUTRAL"