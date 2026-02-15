param(
    [string]$DateStamp = (Get-Date -Format "yyyyMMdd"),
    [string]$StudyId = ("mcp-top50-" + (Get-Date -Format "yyyy-MM")),
    [string]$SelectionCsv = "",
    [switch]$SkipSemgrep,
    [switch]$SkipGitleaks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$benchRoot = Join-Path $repoRoot "docs\benchmarks\top50"
$dataDir = Join-Path $benchRoot "data"
$reportsDir = Join-Path $benchRoot "reports"
$workDir = Join-Path $repoRoot ".tmp\top50-study"

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

if (-not $SelectionCsv) {
    $SelectionCsv = Join-Path $dataDir ("top50_selection_{0}.csv" -f $DateStamp)
}

$findingsOut = Join-Path $reportsDir ("top50_findings_{0}.jsonl" -f $DateStamp)
$summaryOut = Join-Path $reportsDir ("top50_summary_{0}.json" -f $DateStamp)

if (-not (Test-Path $SelectionCsv)) {
    throw "Selection CSV not found: $SelectionCsv"
}

$targets = Import-Csv $SelectionCsv
if ($targets.Count -eq 0) {
    throw "Selection CSV is empty: $SelectionCsv"
}

if (Test-Path $findingsOut) {
    Remove-Item -Force $findingsOut
}

$durations = @()
$severityCounts = @{
    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0
}
$targetsWithHiCrit = 0

foreach ($t in $targets) {
    $targetId = $t.target_id
    $repoUrl = $t.repo_url
    $snapshotRef = $t.snapshot_ref

    if (-not $targetId -or -not $repoUrl) {
        Write-Warning "Skipping invalid row (missing target_id/repo_url)."
        continue
    }

    $targetPath = Join-Path $workDir (($targetId -replace "[^a-zA-Z0-9._-]", "_"))
    if (Test-Path $targetPath) {
        Remove-Item -Recurse -Force $targetPath
    }

    Write-Host "Cloning $targetId"
    git clone --depth 1 $repoUrl $targetPath | Out-Null

    if ($snapshotRef) {
        Push-Location $targetPath
        try {
            git fetch --depth 1 origin $snapshotRef | Out-Null
            git checkout $snapshotRef | Out-Null
        } catch {
            Write-Warning "Could not checkout snapshot_ref=$snapshotRef for $targetId. Continuing with default HEAD."
        } finally {
            Pop-Location
        }
    }

    $start = Get-Date

    # agentsec JSON scan (fail-on none to collect all findings)
    $agentsecJson = Join-Path $targetPath "agentsec-top50.json"
    & agentsec scan $targetPath -o json -f $agentsecJson --fail-on none --quiet

    $targetHiCrit = $false
    if (Test-Path $agentsecJson) {
        $report = Get-Content $agentsecJson -Raw | ConvertFrom-Json
        foreach ($f in $report.findings) {
            $sev = ($f.severity.ToString()).ToLowerInvariant()
            if ($severityCounts.ContainsKey($sev)) {
                $severityCounts[$sev] += 1
            }
            if ($sev -eq "critical" -or $sev -eq "high") {
                $targetHiCrit = $true
            }

            $record = [ordered]@{
                study_id = $StudyId
                target_id = $targetId
                source_type = if ($t.source_type) { $t.source_type } else { "github" }
                snapshot_ref = if ($snapshotRef) { $snapshotRef } else { "HEAD" }
                scanner = "agentsec"
                finding_id = if ($f.id) { $f.id } else { "unknown" }
                severity = $sev
                category = if ($f.category) { ($f.category.ToString()).ToLowerInvariant() } else { "other" }
                title = $f.title
                evidence = if ($f.evidence) { $f.evidence } else { $null }
                location = if ($f.file_path) { $f.file_path } else { $null }
                confidence = "needs_review"
                remediation = if ($f.remediation -and $f.remediation.summary) { $f.remediation.summary } else { $null }
                timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
            }
            ($record | ConvertTo-Json -Compress) | Add-Content -Path $findingsOut
        }
    }

    if ($targetHiCrit) {
        $targetsWithHiCrit += 1
    }

    # Optional: semgrep and gitleaks execution can be integrated here.
    if (-not $SkipSemgrep) {
        Write-Host "Semgrep step placeholder for $targetId"
    }
    if (-not $SkipGitleaks) {
        Write-Host "Gitleaks step placeholder for $targetId"
    }

    $elapsed = ((Get-Date) - $start).TotalSeconds
    $durations += $elapsed
}

$sorted = $durations | Sort-Object
$median = if ($sorted.Count -gt 0) { $sorted[[int][math]::Floor(($sorted.Count - 1) * 0.50)] } else { 0.0 }
$p95 = if ($sorted.Count -gt 0) { $sorted[[int][math]::Floor(($sorted.Count - 1) * 0.95)] } else { 0.0 }

$totalFindings =
    $severityCounts.critical +
    $severityCounts.high +
    $severityCounts.medium +
    $severityCounts.low +
    $severityCounts.info

$summary = [ordered]@{
    study_id = $StudyId
    snapshot_date = (Get-Date -Format "yyyy-MM-dd")
    targets_scanned = $targets.Count
    targets_with_critical_or_high = $targetsWithHiCrit
    critical_findings = $severityCounts.critical
    high_findings = $severityCounts.high
    medium_findings = $severityCounts.medium
    low_findings = $severityCounts.low
    info_findings = $severityCounts.info
    avg_findings_per_target = if ($targets.Count -gt 0) { [math]::Round($totalFindings / $targets.Count, 4) } else { 0.0 }
    runtime_median_seconds = [math]::Round($median, 4)
    runtime_p95_seconds = [math]::Round($p95, 4)
    false_positive_rate_sampled = 0.0
    notes = @(
        "Set confidence via manual review for critical/high findings.",
        "Run semgrep/gitleaks integration before final publication."
    )
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryOut

Write-Host "Done."
Write-Host "Findings: $findingsOut"
Write-Host "Summary : $summaryOut"
