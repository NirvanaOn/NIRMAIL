
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIRMAIL | Email Authentication Analyzer</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">

<style>
:root {
    --bg-main: #05010d;
    --bg-card: #0f0625;
    --purple: #a855f7;
    --purple-soft: #c084fc;
    --text-main: #e5e7eb;
    --text-muted: #9ca3af;
    --border: rgba(168,85,247,0.35);
}

* {
    box-sizing: border-box;
    font-family: Inter, system-ui, sans-serif;
}

body {
    margin: 0;
    min-height: 100vh;
    background: radial-gradient(circle at top, #1a0638 0%, var(--bg-main) 60%);
    color: var(--text-main);
    display: flex;
    align-items: center;
    justify-content: center;
}

.container {
    max-width: 900px;
    padding: 40px 24px;
    text-align: center;
}

h1 {
    font-size: 44px;
    margin: 0;
    color: var(--purple-soft);
}

.subtitle {
    margin-top: 14px;
    font-size: 17px;
    color: var(--text-muted);
}

.card {
    margin-top: 40px;
    background: linear-gradient(145deg, #0f0625, #140833);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 36px;
}

.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 24px;
    margin-top: 30px;
    text-align: left;
}

.feature {
    background: #070314;
    border-radius: 14px;
    padding: 22px;
    border: 1px solid rgba(255,255,255,0.08);
}

.feature h3 {
    margin-top: 0;
    font-size: 18px;
    color: var(--purple-soft);
}

.feature p {
    font-size: 14px;
    color: var(--text-muted);
    line-height: 1.6;
}

.btn {
    display: inline-block;
    margin-top: 36px;
    padding: 14px 32px;
    border-radius: 14px;
    background: linear-gradient(135deg, #7c3aed, #a855f7);
    color: #fff;
    font-size: 16px;
    font-weight: 600;
    text-decoration: none;
    transition: transform .15s ease, box-shadow .15s ease;
}

.btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 12px 30px rgba(168,85,247,0.45);
}

.footer {
    margin-top: 36px;
    font-size: 13px;
    color: var(--text-muted);
}
</style>
</head>

<body>
<div class="container">

<h1>NIRMAIL</h1>
<div class="subtitle">
    Full Email Authentication Analyzer — SPF · DKIM · DMARC
</div>

<div class="card">
    <p>
        NIRMAIL analyzes email authentication using the same logic
        mail servers use in production.
        It evaluates <strong>SPF</strong>, <strong>DKIM</strong>,
        and <strong>DMARC</strong> together to produce a final verdict.
    </p>

    <div class="features">
        <div class="feature">
            <h3>SPF Analysis</h3>
            <p>
                Validates sender IPs, evaluates DNS mechanisms,
                enforces lookup limits, and provides a decision trace.
            </p>
        </div>

        <div class="feature">
            <h3>DKIM Verification</h3>
            <p>
                Performs real cryptographic verification using
                uploaded EML files and selector DNS records.
            </p>
        </div>

        <div class="feature">
            <h3>DMARC Evaluation</h3>
            <p>
                Applies alignment rules and policy logic to determine
                the final authentication outcome.
            </p>
        </div>
    </div>

    <a href="check.php" class="btn">Start Email Authentication Check</a>
</div>

<div class="footer">
    Built by <strong>NIRMAIL</strong> · Email Security Research Tool
</div>

</div>
</body>
</html>
