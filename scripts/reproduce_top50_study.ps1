param(
    [string]$DateStamp = (Get-Date -Format "yyyyMMdd"),
    [string]$StudyId = ("mcp-top50-" + (Get-Date -Format "yyyy-MM")),
    [string]$SelectionCsv = "",
    [switch]$SkipSemgrep,
    [switch]$SkipGitleaks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-ToolAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-SanitizedLocation {
    param(
        [string]$TargetId,
        [string]$RawPath,
        [int]$Line = 0
    )

    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        return $null
    }

    $p = $RawPath.Replace('\\', '/')
    $safeTarget = ($TargetId -replace '/', '_')
    $marker = "/$safeTarget/"
    $idx = $p.ToLowerInvariant().IndexOf($marker.ToLowerInvariant())

    if ($idx -ge 0) {
        $location = "$TargetId/" + $p.Substring($idx + $marker.Length)
    } elseif ($p -match '^[A-Za-z]:/') {
        $location = [System.IO.Path]::GetFileName($p)
    } else {
        $location = $p
    }

    if ($Line -gt 0) {
        return "${location}:$Line"
    }
    return $location
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$benchRoot = Join-Path $repoRoot "docs\benchmarks\top50"
$dataDir = Join-Path $benchRoot "data"
$reportsDir = Join-Path $benchRoot "reports"
$workDir = Join-Path $repoRoot ".tmp\top50-study"
$semgrepRules = Join-Path $repoRoot "scripts\semgrep-top50-rules.yml"

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
$targetsClonedSuccessfully = 0
$scannerCounts = @{
    agentsec = 0
    semgrep = 0
    gitleaks = 0
}

$semgrepAvailable = (-not $SkipSemgrep) -and (Test-ToolAvailable -Name "semgrep")
$gitleaksAvailable = (-not $SkipGitleaks) -and (Test-ToolAvailable -Name "gitleaks")

if ((-not $SkipSemgrep) -and (-not $semgrepAvailable)) {
    Write-Warning "semgrep not found on PATH; semgrep baseline scan will be skipped."
}
if ((-not $SkipGitleaks) -and (-not $gitleaksAvailable)) {
    Write-Warning "gitleaks not found on PATH; gitleaks baseline scan will be skipped."
}

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
    try {
        git clone --depth 1 $repoUrl $targetPath | Out-Null
        $targetsClonedSuccessfully += 1
    } catch {
        Write-Warning "Clone failed for $targetId. Skipping target."
        continue
    }

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
    $targetHiCrit = $false

    # agentsec JSON scan
    $agentsecJson = Join-Path $targetPath "agentsec-top50.json"
    & agentsec scan $targetPath -o json -f $agentsecJson --fail-on none --quiet

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
                location = Get-SanitizedLocation -TargetId $targetId -RawPath $f.file_path
                confidence = "needs_review"
                remediation = if ($f.remediation -and $f.remediation.summary) { $f.remediation.summary } else { $null }
                timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
            }
            ($record | ConvertTo-Json -Compress) | Add-Content -Path $findingsOut
            $scannerCounts.agentsec += 1
        }
    }

    if ($semgrepAvailable) {
        $semgrepJson = Join-Path $targetPath "semgrep-top50.json"
        & semgrep scan --json --config $semgrepRules --output $semgrepJson $targetPath | Out-Null

        if (Test-Path $semgrepJson) {
            $semgrepReport = Get-Content $semgrepJson -Raw | ConvertFrom-Json
            foreach ($r in $semgrepReport.results) {
                $rawSev = if ($r.extra -and $r.extra.severity) { $r.extra.severity.ToString().ToUpperInvariant() } else { "INFO" }
                $sev = switch ($rawSev) {
                    "ERROR" { "high" }
                    "WARNING" { "medium" }
                    default { "low" }
                }
                if ($severityCounts.ContainsKey($sev)) {
                    $severityCounts[$sev] += 1
                }
                if ($sev -eq "critical" -or $sev -eq "high") {
                    $targetHiCrit = $true
                }

                $line = 0
                if ($r.start -and $r.start.line) {
                    $line = [int]$r.start.line
                }

                $record = [ordered]@{
                    study_id = $StudyId
                    target_id = $targetId
                    source_type = if ($t.source_type) { $t.source_type } else { "github" }
                    snapshot_ref = if ($snapshotRef) { $snapshotRef } else { "HEAD" }
                    scanner = "semgrep"
                    finding_id = if ($r.check_id) { $r.check_id } else { "semgrep" }
                    severity = $sev
                    category = "other"
                    title = if ($r.extra -and $r.extra.message) { $r.extra.message } else { "semgrep finding" }
                    evidence = $null
                    location = Get-SanitizedLocation -TargetId $targetId -RawPath $r.path -Line $line
                    confidence = "needs_review"
                    remediation = $null
                    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
                }
                ($record | ConvertTo-Json -Compress) | Add-Content -Path $findingsOut
                $scannerCounts.semgrep += 1
            }
        }
    }

    if ($gitleaksAvailable) {
        $gitleaksJson = Join-Path $targetPath "gitleaks-top50.json"
        & gitleaks detect --source $targetPath --report-format json --report-path $gitleaksJson --redact --no-banner | Out-Null

        if (Test-Path $gitleaksJson) {
            $gitleaksReport = Get-Content $gitleaksJson -Raw | ConvertFrom-Json
            if ($gitleaksReport -is [System.Array]) {
                foreach ($r in $gitleaksReport) {
                    $sev = "high"
                    $severityCounts[$sev] += 1
                    $targetHiCrit = $true

                    $line = 0
                    if ($r.StartLine) {
                        $line = [int]$r.StartLine
                    }

                    $record = [ordered]@{
                        study_id = $StudyId
                        target_id = $targetId
                        source_type = if ($t.source_type) { $t.source_type } else { "github" }
                        snapshot_ref = if ($snapshotRef) { $snapshotRef } else { "HEAD" }
                        scanner = "gitleaks"
                        finding_id = if ($r.RuleID) { $r.RuleID } else { "gitleaks" }
                        severity = $sev
                        category = "secret"
                        title = if ($r.Description) { "Gitleaks: $($r.Description)" } else { "Gitleaks potential secret" }
                        evidence = $null
                        location = Get-SanitizedLocation -TargetId $targetId -RawPath $r.File -Line $line
                        confidence = "needs_review"
                        remediation = "Rotate secret and remove from git history if real."
                        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
                    }
                    ($record | ConvertTo-Json -Compress) | Add-Content -Path $findingsOut
                    $scannerCounts.gitleaks += 1
                }
            }
        }
    }

    if ($targetHiCrit) {
        $targetsWithHiCrit += 1
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

$notes = @(
    "Confidence is set to needs_review pending manual triage.",
    "false_positive_rate_sampled is unset until manual sampling is complete."
)
if ($semgrepAvailable -or $gitleaksAvailable) {
    $notes += "Baseline scans included available tools (semgrep/gitleaks) for this run."
} else {
    $notes += "Run with semgrep and gitleaks installed to include baseline scanner output."
}

$summary = [ordered]@{
    study_id = $StudyId
    snapshot_date = (Get-Date -Format "yyyy-MM-dd")
    targets_scanned = $targets.Count
    targets_cloned_successfully = $targetsClonedSuccessfully
    targets_with_critical_or_high = $targetsWithHiCrit
    critical_findings = $severityCounts.critical
    high_findings = $severityCounts.high
    medium_findings = $severityCounts.medium
    low_findings = $severityCounts.low
    info_findings = $severityCounts.info
    scanner_counts = $scannerCounts
    avg_findings_per_target = if ($targetsClonedSuccessfully -gt 0) { [math]::Round($totalFindings / $targetsClonedSuccessfully, 4) } else { 0.0 }
    runtime_median_seconds = [math]::Round($median, 4)
    runtime_p95_seconds = [math]::Round($p95, 4)
    false_positive_rate_sampled = $null
    notes = $notes
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryOut

Write-Host "Done."
Write-Host "Findings: $findingsOut"
Write-Host "Summary : $summaryOut"
