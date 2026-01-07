# 📧 NIRMAIL — Email Authentication Analyzer  
**SPF · DKIM · DMARC · ARC**

NIRMAIL is a **standards-focused email authentication analysis tool** designed to present  
**clear, accurate authentication results** without exposing sensitive or unsafe internals.

The project is intended for **learning, auditing, and security review**, not exploitation.

---

## 🎯 Purpose

- Deliver **clear and concise authentication outcomes**
- Present results in **simple, professional language**
- Remain **RFC-aligned** and implementation-safe
- Avoid disclosure of attack paths or bypass logic

---

## 🚀 Supported Authentication Checks

### 1️⃣ SPF — Sender Policy Framework
- Evaluates sender IP authorization
- Supports standard SPF mechanisms
- Enforces DNS lookup limits
- Produces a clear pass/fail outcome

---

### 2️⃣ DKIM — DomainKeys Identified Mail
- Verifies DKIM signatures
- Safely handles multiple signatures
- Reports verification status clearly
- Used strictly for alignment evaluation

---

### 3️⃣ ARC — Authenticated Received Chain
- Detects ARC-related headers
- Treated as **informational only**
- No trust or policy enforcement based on ARC

---

### 4️⃣ DMARC — Policy Enforcement
- Evaluates SPF and DKIM alignment
- Supports strict and relaxed alignment modes
- Applies domain policy accurately
- Returns a final decision:
  - **ALLOW**
  - **QUARANTINE**
  - **REJECT**

---

## 🧩 Output Design

- Human-readable explanations
- Structured JSON suitable for API and UI use
- No cryptographic internals or bypass details
- Safe for demonstrations and documentation

---

## ⚠️ Notes

- ARC is informational only
- DKIM failures may occur during forwarding
- DMARC decisions strictly follow published policy
- Analysis-only tool — no email transmission

---

## 👤 Author

**Om Sonani (Nirvana)**  
Cybersecurity student

**NIRMAIL — clear email authentication, without overexposure.** 📬
