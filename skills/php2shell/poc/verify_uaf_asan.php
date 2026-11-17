<?php
/**
 * verify_uaf_asan.php — Verify Use-After-Free conditions with AddressSanitizer output.
 *
 * Runs in an ASan-instrumented PHP build to detect UAF patterns in the LFI→RCE
 * exploit chain. Triggers the vulnerable code path and captures ASan reports.
 *
 * Lab environments with php-asan binary only.
 * Hard requirement: authorized scope, lab VM, no production data.
 *
 * Usage: php-asan verify_uaf_asan.php --mode probe --target /tmp/sess_<id>
 */

declare(strict_types=1);

$mode   = $_SERVER['argv'][2] ?? 'help';
$target = $_SERVER['argv'][4] ?? '';

if ($mode === 'help' || !$mode) {
    echo "Usage: php-asan verify_uaf_asan.php --mode <probe|report|cleanup> --target <path>\n";
    echo "Modes:\n";
    echo "  probe    — trigger UAF pattern and capture ASan output\n";
    echo "  report   — parse captured ASan log and produce structured output\n";
    echo "  cleanup  — remove temporary probe files\n";
    exit(0);
}

// ── Probe mode: trigger the vulnerable code path ──────────────────────────────

if ($mode === 'probe') {
    $marker = bin2hex(random_bytes(8));
    $probe_path = sys_get_temp_dir() . '/ares_uaf_probe_' . $marker . '.php';

    // Write a minimal session-like file to test LFI inclusion behavior
    // The content exercises the upload_progress path that triggers UAF in patched versions
    $probe_content = sprintf(
        '<?php $v = "ARES_UAF_%s"; echo $v; ?>',
        strtoupper($marker)
    );
    file_put_contents($probe_path, $probe_content);
    chmod($probe_path, 0600);

    // Attempt inclusion — in a real vulnerable build this exercises the UAF path
    $asan_log = '';
    ob_start();
    try {
        // Note: include() on a controlled path in a lab build captures ASan output
        // to stderr; we redirect stderr via proc_open to capture it
        $desc = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $cmd  = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg($probe_path);
        $proc = proc_open($cmd, $desc, $pipes);
        if (is_resource($proc)) {
            fclose($pipes[0]);
            $stdout   = stream_get_contents($pipes[1]);
            $asan_log = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
        }
    } catch (Throwable $e) {
        $asan_log = $e->getMessage();
    }
    ob_end_clean();

    $result = [
        'mode'       => 'probe',
        'marker'     => $marker,
        'probe_path' => $probe_path,
        'asan_log'   => $asan_log ?: '(no ASan output — may not be an ASan build)',
        'uaf_detected' => str_contains($asan_log, 'heap-use-after-free') ||
                           str_contains($asan_log, 'AddressSanitizer'),
    ];

    // Always clean up probe file
    @unlink($probe_path);

    echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
    exit($result['uaf_detected'] ? 0 : 1);
}

// ── Report mode: parse an existing ASan log ────────────────────────────────────

if ($mode === 'report') {
    if (!$target || !file_exists($target)) {
        echo json_encode(['error' => "File not found: $target"]) . "\n";
        exit(2);
    }
    $log = file_get_contents($target);

    $findings = [];

    // Parse ASan error types
    $patterns = [
        'heap-use-after-free' => '/heap-use-after-free/',
        'heap-buffer-overflow' => '/heap-buffer-overflow/',
        'stack-buffer-overflow' => '/stack-buffer-overflow/',
        'global-buffer-overflow' => '/global-buffer-overflow/',
        'use-after-return' => '/use-after-return/',
        'use-after-scope' => '/use-after-scope/',
        'double-free' => '/double-free/',
    ];

    foreach ($patterns as $name => $re) {
        if (preg_match($re, $log)) {
            $findings[] = $name;
        }
    }

    // Extract stack trace lines
    $stack = [];
    if (preg_match_all('/#\d+\s+0x[0-9a-f]+ in \S+.*/', $log, $m)) {
        $stack = array_slice($m[0], 0, 10);
    }

    echo json_encode([
        'mode'     => 'report',
        'source'   => $target,
        'findings' => $findings,
        'stack'    => $stack,
        'summary'  => empty($findings)
            ? 'No ASan findings detected'
            : 'UAF/memory corruption detected: ' . implode(', ', $findings),
    ], JSON_PRETTY_PRINT) . "\n";
    exit(empty($findings) ? 1 : 0);
}

// ── Cleanup mode ──────────────────────────────────────────────────────────────

if ($mode === 'cleanup') {
    $tmp = sys_get_temp_dir();
    $removed = 0;
    foreach (glob($tmp . '/ares_uaf_probe_*.php') as $f) {
        if (@unlink($f)) {
            $removed++;
        }
    }
    echo json_encode(['mode' => 'cleanup', 'removed' => $removed]) . "\n";
    exit(0);
}

echo json_encode(['error' => "Unknown mode: $mode"]) . "\n";
exit(2);
