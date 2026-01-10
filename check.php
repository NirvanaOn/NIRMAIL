<?php
$error  = null;
$result = null;

/* ================= SPF TREE RENDERER ================= */
function render_spf_tree(array $node, int $level = 0): void
{
    $indent = $level * 22;

    echo "<div class='spf-tree-node' style='margin-left: {$indent}px'>";
    echo "<div class='spf-tree-domain'>{$node['domain']}</div>";

    if (!empty($node['spf'])) {
        echo "<div class='spf-tree-record'><code>{$node['spf']}</code></div>";
    }

    if (!empty($node['mechanisms'])) {
        echo "<ul class='spf-tree-mechs'>";
        foreach ($node['mechanisms'] as $m) {
            echo "<li>{$m}</li>";
        }
        echo "</ul>";
    }

    if (!empty($node['children'])) {
        echo "<details open class='spf-tree-children'>";
        echo "<summary>Includes / Redirects</summary>";
        foreach ($node['children'] as $child) {
            render_spf_tree($child, $level + 1);
        }
        echo "</details>";
    }

    echo "</div>";
}

/* ================= FORM HANDLER ================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $domain     = trim($_POST['domain'] ?? '');
    $sender_ip = trim($_POST['sender_ip'] ?? '');
    $mail_from = trim($_POST['mail_from'] ?? '');
    $helo      = trim($_POST['helo'] ?? '');

    if ($domain === '' || $sender_ip === '') {
        $error = 'Domain and Sender IP are required.';
    } else {

        $payload = [
            'domain'     => $domain,
            'sender_ip' => $sender_ip,
            'mail_from' => $mail_from ?: null,
            'helo'      => $helo ?: null,
        ];

        if (!empty($_FILES['eml_file']['tmp_name'])) {
            $payload['raw_email_b64'] = base64_encode(
                file_get_contents($_FILES['eml_file']['tmp_name'])
            );
        }

        $ctx = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\n",
                'content' => json_encode($payload),
                'timeout' => 30
            ]
        ]);

        $response = @file_get_contents('http://127.0.0.1:8000/check', false, $ctx);

        if ($response === false) {
            $error = 'Backend API unreachable.';
        } else {
            $result = json_decode($response, true);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIRMAIL | Email Authentication Check</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="check.css">
</head>

<body>
<div class="container">

<a href="home.php" class="back">← Back to Home</a>

<header class="page-header">
    <h1>Email Authentication Check</h1>
    <p>SPF → DKIM → DMARC (RFC-accurate evaluation)</p>
</header>

<!-- ================= INPUT ================= -->
<section class="card input-card">
<h2 class="section-title">Input Details</h2>

<form method="post" enctype="multipart/form-data">
<div class="grid">

    <div class="field">
        <label>Domain</label>
        <input name="domain" required>
    </div>

    <div class="field">
        <label>Sender IP</label>
        <input name="sender_ip" required>
    </div>

    <div class="field">
        <label>MAIL FROM (optional)</label>
        <input name="mail_from">
    </div>

    <div class="field">
        <label>HELO / EHLO (optional)</label>
        <input name="helo">
    </div>

    <div class="field full">
        <label>Email (.eml)</label>
        <div class="file-upload">
            <input type="file" id="eml_file" name="eml_file" accept=".eml">
            <label for="eml_file" class="file-btn">Upload .eml</label>
            <span class="file-name" id="file-name">No file selected</span>
        </div>
        <small>Required only for DKIM verification</small>
    </div>

</div>

<button type="submit" class="action-btn">Run Authentication Check</button>
</form>
</section>

<?php if ($error): ?>
<section class="card error-card"><?= htmlspecialchars($error) ?></section>
<?php endif; ?>

<?php if ($result): ?>

<!-- ================= SPF ================= -->
<section class="card spf-card">
<h2 class="section-title">
    SPF Result
    <span class="status-badge <?= strtolower($result['spf']['result']) ?>">
        <?= $result['spf']['result'] ?>
    </span>
</h2>

<div class="result-grid">
    <div><span>Domain</span><strong><?= $result['spf']['domain'] ?></strong></div>
    <div><span>DNS Lookups</span><strong><?= $result['spf']['dns_lookups'] ?> / 10</strong></div>
</div>

<details>
<summary>Decision Trace</summary>
<pre><?php foreach ($result['spf']['trace'] as $t) echo "• $t\n"; ?></pre>
</details>

<details open>
<summary>Evaluation Tree</summary>
<div class="spf-tree">
<?php render_spf_tree($result['spf']['tree']); ?>
</div>
</details>
</section>

<!-- ================= DKIM ================= -->
<section class="card dkim-card">
<h2 class="section-title">
    DKIM Result
    <span class="status-badge <?= strtolower($result['dkim']['result']) ?>">
        <?= $result['dkim']['result'] ?>
    </span>
</h2>

<?php if (!$result['dkim']['performed']): ?>
<p>DKIM check skipped (no EML provided)</p>
<?php else: ?>

<div class="result-grid">
    <div><span>d= Domain</span><strong><?= $result['dkim']['domain'] ?></strong></div>
    <div><span>Header-From</span><strong><?= $result['dkim']['header_from_domain'] ?></strong></div>
    <div><span>Aligned</span><strong><?= $result['dkim']['aligned'] ? 'YES' : 'NO' ?></strong></div>
</div>

<table>
<thead>
<tr>
<th>Domain</th><th>Selector</th><th>Algorithm</th><th>Canonicalization</th>
</tr>
</thead>
<tbody>
<?php foreach ($result['dkim']['signatures'] as $s): ?>
<tr>
<td><?= $s['domain'] ?></td>
<td><?= $s['selector'] ?></td>
<td><?= $s['algorithm'] ?></td>
<td><?= $s['canonicalization'] ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>

<details>
<summary>DKIM Decision Tree</summary>
<pre><?php foreach ($result['dkim']['tree'] as $l) echo "$l\n"; ?></pre>
</details>

<?php endif; ?>
</section>

<!-- ================= DMARC (FINAL) ================= -->
<section class="card verdict-card <?= strtolower($result['dmarc']['raw']['dmarc_result']) ?>">
<h2 class="verdict-title">
    DMARC Final Verdict
    <span class="status-badge <?= strtolower($result['dmarc']['raw']['dmarc_result']) ?>">
        <?= $result['dmarc']['raw']['dmarc_result'] ?>
    </span>
</h2>

<div class="result-grid">
    <div><span>Policy</span><strong><?= $result['dmarc']['raw']['policy'] ?></strong></div>
    <div><span>SPF Aligned</span><strong><?= $result['dmarc']['raw']['spf_aligned']?'YES':'NO' ?></strong></div>
    <div><span>DKIM Aligned</span><strong><?= $result['dmarc']['raw']['dkim_aligned']?'YES':'NO' ?></strong></div>
    <div><span>Enforcement</span><strong><?= $result['dmarc']['raw']['enforcement'] ?></strong></div>
</div>

<details>
<summary>DMARC Decision Tree</summary>
<pre><?php foreach ($result['dmarc']['tree'] as $l) echo "$l\n"; ?></pre>
</details>
</section>

<?php endif; ?>

</div>

<script>
document.getElementById('eml_file')?.addEventListener('change', function () {
    document.getElementById('file-name').textContent =
        this.files.length ? this.files[0].name : 'No file selected';
});
</script>

</body>
</html>
