from typing import Optional
from mail_engine import run_mail_check


def main():
    print("========== MAIL AUTH CHECK (SPF / DKIM / DMARC) ==========\n")

    domain = input("Enter domain: ").strip().lower()
    sender_ip = input("Enter sender IP: ").strip()

    mail_from = (
        input(
            "Enter MAIL FROM (optional, for macros; e.g. user@example.com) "
            "[press Enter to skip]: "
        ).strip()
        or None
    )

    helo = (
        input(
            "Enter HELO/EHLO domain (optional) "
            "[press Enter to skip]: "
        ).strip()
        or None
    )

    raw_email: Optional[bytes] = None

    eml_path = (
        input(
            "\nEnter .eml file path for DKIM verification "
            "[press Enter to skip]: "
        )
        .strip()
        .strip('"')
        .strip("'")
    )

    if eml_path:
        try:
            with open(eml_path, "rb") as f:
                raw_email = f.read()
        except FileNotFoundError:
            print("EML file not found. DKIM will be skipped.")
        except Exception as e:
            print("Failed to read EML file:", str(e))


    result = run_mail_check(
        domain=domain,
        sender_ip=sender_ip,
        mail_from=mail_from,
        helo=helo,
        raw_email=raw_email,
    )

    print("\n========== SPF RESULT ==========\n")
    spf = result["spf"]
    print("Result      :", spf["result"])
    print("SPF Domain  :", spf["domain"])
    print("DNS Lookups :", spf["dns_lookups"])

    print("\nSPF Decision Trace:")
    for step in spf["trace"]:
        print("•", step)

    print("\n========== DKIM RESULT ==========\n")
    dkim = result["dkim"]

    if not dkim["performed"]:
        print("DKIM check skipped (no EML provided)")
    else:
        print("Result       :", dkim["result"])
        print("Domain (d=)  :", dkim["domain"])
        print("Aligned      :", dkim["aligned"])

        print("\nDKIM Tree:")
        for line in dkim["tree"]:
            print(line)

    print("\n========== DMARC RESULT ==========\n")
    dmarc = result["dmarc"]

    print("DMARC Present :", dmarc["present"])
    print("DMARC Result  :", dmarc["result"])
    print("Policy        :", dmarc["policy"])
    print("Alignment     :", dmarc["alignment"])
    print("Reason        :", dmarc["reason"])

    print("\nDMARC Tree:")
    for line in dmarc["tree"]:
        print(line)

    print("\n========== END ==========\n")


if __name__ == "__main__":
    main()
