from typing import Optional, Dict, Any
import re

from spf_extractor import build_spf_tree
from spf_evaluator import evaluate_spf

from dkim_evaluator import check_dkim, build_dkim_tree
from dmarc_evaluator import evaluate_dmarc, build_dmarc_tree


def extract_header_from_domain(raw_email: bytes) -> Optional[str]:
    headers = raw_email.split(b"\r\n\r\n", 1)[0]

    m = re.search(
        rb"^From:.*<[^@>]+@([^>]+)>",
        headers,
        re.IGNORECASE | re.MULTILINE,
    )
    if m:
        return m.group(1).decode(errors="ignore").strip().lower()

    m = re.search(
        rb"^From:.*@([^\s>]+)",
        headers,
        re.IGNORECASE | re.MULTILINE,
    )
    if m:
        return m.group(1).decode(errors="ignore").strip().lower()

    return None


def run_mail_check(
    domain: str,
    sender_ip: str,
    mail_from: Optional[str],
    helo: Optional[str],
    raw_email: Optional[bytes],
) -> Dict[str, Any]:

    result: Dict[str, Any] = {}

    spf_tree = build_spf_tree(domain)

    spf_trace = {"steps": [], "lookups": 0}

    spf_result = evaluate_spf(
        domain,
        sender_ip,
        trace=spf_trace,
        mail_from=mail_from,
        helo=helo,
    )

    if mail_from and "@" in mail_from:
        spf_domain = mail_from.split("@", 1)[1].lower()
    else:
        spf_domain = domain

    result["spf"] = {
        "result": spf_result,
        "domain": spf_domain,
        "dns_lookups": spf_trace.get("lookups", 0),
        "trace": spf_trace["steps"],
        "tree": spf_tree,
    }


    dkim_result = "NONE"
    dkim_domain = None
    dkim_tree = None
    header_from_domain = domain

    if raw_email:
        extracted_from = extract_header_from_domain(raw_email)
        if extracted_from:
            header_from_domain = extracted_from

        dkim_info = check_dkim(
            raw_email,
            header_from_domain=header_from_domain,
        )

        dkim_result = dkim_info.get("dkim_result", "NONE")
        dkim_domain = dkim_info.get("dkim_domain")

        dkim_tree = build_dkim_tree(dkim_info, header_from_domain)

        result["dkim"] = {
            "performed": True,
            "header_from_domain": header_from_domain,
            "result": dkim_result,
            "domain": dkim_domain,
            "aligned": dkim_info.get("dkim_aligned"),
            "signatures": dkim_info.get("dkim_signatures"),
            "tree": dkim_tree,
            "raw": dkim_info,
        }

    else:
        result["dkim"] = {
            "performed": False,
            "result": "NONE",
            "domain": None,
            "aligned": False,
        }


    dmarc = evaluate_dmarc(
        header_from_domain=header_from_domain,
        spf_result=spf_result,
        spf_domain=spf_domain,
        dkim_result=dkim_result,
        dkim_domain=dkim_domain,
    )

    dmarc_tree = build_dmarc_tree(dmarc)

    result["dmarc"] = {
        "present": dmarc.get("present"),
        "result": dmarc.get("result"),
        "policy": dmarc.get("policy"),
        "alignment": dmarc.get("alignment"),
        "reason": dmarc.get("reason"),
        "tree": dmarc_tree,
        "raw": dmarc,
    }

    return result
