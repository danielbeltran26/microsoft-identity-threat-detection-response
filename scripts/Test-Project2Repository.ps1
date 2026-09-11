[CmdletBinding()]
param(
    [string]$RepositoryPath = (Split-Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Project 2 completed-repository validation" -ForegroundColor Cyan
Write-Host "This script is read-only and excludes temporary and Git metadata.`n"

if (-not (Test-Path -LiteralPath $RepositoryPath -PathType Container)) {
    throw "Repository not found: $RepositoryPath"
}

$ExpectedCorePaths = @(
    "README.md",
    "lessons-learned.md",
    "architecture\01-identity-threat-detection-response-architecture.md",
    "data\controlled-test-object-manifest.csv",
    "docs\Baseline-and-Recovery-Checkpoint.md",
    "docs\High-Value-Group-Membership-Change.md",
    "docs\Identity-Telemetry-Schema-Profile.md",
    "docs\Integrated-Identity-Attack-Chain.md",
    "docs\Investigation-Containment-and-Recovery.md",
    "docs\Password-Spray-Detection.md",
    "docs\Repository-Completion-and-Quality-Review.md",
    "docs\Production-Limitations-and-Improvements.md",
    "docs\Successful-Authentication-After-Repeated-Failures.md",
    "queries\IDTR001-PasswordSpray.kql",
    "queries\IDTR002-SuccessAfterFailures.kql",
    "queries\IDTR003-HighValueGroupMembershipChange.kql",
    "queries\IDTR004-IntegratedIdentityAttackChain.kql",
    "queries\Investigate-IDTRIntegratedIncident.kql",
    "queries\Profile-IdentitySecurityEvents.kql",
    "queries\Validate-IDTRTelemetryBaseline.kql",
    "runbooks\01-identity-threat-detection-response-runbook.md",
    "scripts\Get-Project1SentinelRuleBaseline.ps1",
    "scripts\Invoke-IDTRIncidentContainment.ps1",
    "scripts\Invoke-IDTRIntegratedAttackChain.ps1",
    "scripts\Invoke-IDTRPasswordSpraySimulation.ps1",
    "scripts\Invoke-IDTRPrivilegedGroupChange.ps1",
    "scripts\Invoke-IDTRSuccessfulLogonAfterFailures.ps1",
    "scripts\New-IDTRLabObjects.ps1",
    "scripts\Restore-IDTRLabState.ps1",
    "scripts\Test-IDTRFinalState.ps1",
    "scripts\Test-IDTRRecoveryState.ps1",
    "scripts\Test-Project2Baseline.ps1",
    "scripts\Test-Project2Repository.ps1"
)

$ExpectedScreenshotNames = @(
    "m01-01-recovery-snapshot.png",
    "m01-02-ad-domain-services.png",
    "m01-03-azure-arc-connected.png",
    "m01-04-ama-extension-succeeded.png",
    "m01-05-dcr-powershell-association.png",
    "m01-06-dcr-security-association.png",
    "m01-07-heartbeat-validation.png",
    "m01-08-securityevent-validation.png",
    "m01-09-powershell-4104-validation.png",
    "m01-10-project1-rules.png",
    "m02-01-idtr-lab-objects.png",
    "m02-02-local-failed-authentication-events.png",
    "m02-03-cloud-failed-authentication-ingestion.png",
    "m02-04-local-successful-authentication-event.png",
    "m02-05-cloud-successful-authentication-ingestion.png",
    "m02-06-local-high-value-group-change-events.png",
    "m02-07-cloud-high-value-group-change-ingestion.png",
    "m02-08-verified-final-safe-state.png",
    "m03-01-idtr001-validated-rule-configuration.png",
    "m03-02-fresh-password-spray-local-events.png",
    "m03-03-fresh-password-spray-cloud-ingestion.png",
    "m03-04-idtr001-generated-alert.png",
    "m03-05-idtr001-incident-alert-grouping.png",
    "m03-06-idtr001-mapped-entities.png",
    "m03-07-verified-final-safe-state.png",
    "m03-08-idtr001-closed-benign-positive.png",
    "m04-01-idtr002-validated-rule-configuration.png",
    "m04-02-idtr002-local-event-sequence.png",
    "m04-03-idtr002-cloud-ingestion.png",
    "m04-04-idtr002-alert-and-incident.png",
    "m04-05-idtr002-mapped-entities.png",
    "m04-06-idtr002-verified-safe-state.png",
    "m04-07-idtr002-closed-benign-positive.png",
    "m05-01-idtr003-local-group-change-events.png",
    "m05-02-idtr003-cloud-group-change-ingestion.png",
    "m05-03-idtr003-validated-rule-configuration.png",
    "m05-04-idtr003-alerts-and-incident.png",
    "m05-05-idtr003-mapped-entities.png",
    "m05-06-idtr003-verified-safe-state.png",
    "m05-07-idtr003-closed-benign-positive.png",
    "m06-01-integrated-chain-baseline.png",
    "m06-02-idtr004-validated-rule-configuration.png",
    "m06-03-integrated-chain-local-sequence.png",
    "m06-04-integrated-chain-cloud-ingestion.png",
    "m06-05-idtr004-alert-and-incident.png",
    "m06-06-idtr004-mapped-entities.png",
    "m06-07-integrated-chain-verified-safe-state.png",
    "m06-08-idtr004-closed-benign-positive.png",
    "m07-01-investigation-response-baseline.png",
    "m07-02-idtr004-response-prerequisites.png",
    "m07-03-controlled-chain-generation.png",
    "m07-04-fresh-chain-cloud-ingestion.png",
    "m07-05-fresh-idtr004-incident.png",
    "m07-06-active-incident-and-tasks.png",
    "m07-07-validated-incident-investigation.png",
    "m07-08-validated-identity-containment.png",
    "m07-09-verified-recovery-state.png",
    "m07-10-post-containment-cloud-telemetry.png",
    "m07-11-completed-tasks-and-analyst-record.png",
    "m07-12-closed-response-workflow.png",
    "m08-01-project1-rules-preserved.png",
    "m08-02-final-powered-off-recovery-snapshot.png"
)

$ExpectedPaths = @(
    $ExpectedCorePaths
    $ExpectedScreenshotNames |
        ForEach-Object { "screenshots\$_" }
) | Sort-Object

$OfficialFiles = @(
    Get-ChildItem `
        -LiteralPath $RepositoryPath `
        -File `
        -Recurse |
    ForEach-Object {
        $RelativePath = $_.FullName.Substring(
            $RepositoryPath.Length
        ).TrimStart("\")

        if (
            $RelativePath -notlike "temporary\*" -and
            $RelativePath -notlike ".git\*"
        ) {
            [pscustomobject]@{
                Item         = $_
                RelativePath = $RelativePath
            }
        }
    }
)

$ActualPaths = @(
    $OfficialFiles.RelativePath |
        Sort-Object
)

$MissingPaths = @(
    $ExpectedPaths |
        Where-Object { $_ -notin $ActualPaths }
)

$UnexpectedPaths = @(
    $ActualPaths |
        Where-Object { $_ -notin $ExpectedPaths }
)

$InventoryMatches = (
    ($ExpectedPaths -join "`n") -eq
    ($ActualPaths -join "`n")
)

$EmptyFiles = @(
    $OfficialFiles |
        Where-Object { $_.Item.Length -eq 0 }
)

$HashRecords = @(
    foreach ($File in $OfficialFiles) {
        [pscustomobject]@{
            RelativePath = $File.RelativePath
            Hash = (
                Get-FileHash `
                    -LiteralPath $File.Item.FullName `
                    -Algorithm SHA256
            ).Hash
        }
    }
)

$DuplicateContentGroups = @(
    $HashRecords |
        Group-Object Hash |
        Where-Object Count -GT 1
)

$UnexpectedVariantFiles = @(
    $OfficialFiles |
        Where-Object {
            $_.Item.Name -match '\(\d+\)(?=\.[^.]+$)'
        }
)

$PowerShellFiles = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".ps1" }
)

$PowerShellParseFailures = @(
    foreach ($File in $PowerShellFiles) {
        $Tokens = $null
        $ParseErrors = $null

        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $File.Item.FullName,
            [ref]$Tokens,
            [ref]$ParseErrors
        )

        if (@($ParseErrors).Count -gt 0) {
            [pscustomobject]@{
                File   = $File.RelativePath
                Errors = @($ParseErrors).Count
            }
        }
    }
)

$PngFiles = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".png" }
)

$ExpectedPngSignature = @(137, 80, 78, 71, 13, 10, 26, 10)

$InvalidPngFiles = @(
    foreach ($File in $PngFiles) {
        $Bytes = [System.IO.File]::ReadAllBytes($File.Item.FullName)
        $SignatureValid = $Bytes.Length -ge 8

        if ($SignatureValid) {
            for ($Index = 0; $Index -lt 8; $Index++) {
                if ($Bytes[$Index] -ne $ExpectedPngSignature[$Index]) {
                    $SignatureValid = $false
                    break
                }
            }
        }

        if (-not $SignatureValid) {
            $File.RelativePath
        }
    }
)

$ExpectedScreenshotCounts = @{
    "01" = 10
    "02" = 8
    "03" = 8
    "04" = 7
    "05" = 7
    "06" = 8
    "07" = 12
    "08" = 2
}

$ScreenshotSequenceFailures = @(
    foreach ($Milestone in $ExpectedScreenshotCounts.Keys) {
        $MilestoneFiles = @(
            $PngFiles |
                Where-Object {
                    $_.Item.Name -like "m$Milestone-*.png"
                }
        )

        $ExpectedNumbers = @(
            1..$ExpectedScreenshotCounts[$Milestone] |
                ForEach-Object { "{0:D2}" -f $_ }
        )

        $ActualNumbers = @(
            $MilestoneFiles |
                ForEach-Object {
                    if ($_.Item.Name -match '^m\d{2}-(\d{2})-') {
                        $Matches[1]
                    }
                } |
                Sort-Object
        )

        if (
            ($ExpectedNumbers -join "`n") -ne
            ($ActualNumbers -join "`n")
        ) {
            [pscustomobject]@{
                Milestone = $Milestone
                Expected  = $ExpectedNumbers -join ","
                Actual    = $ActualNumbers -join ","
            }
        }
    }
)

$MarkdownFiles = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".md" }
)

$BrokenInternalLinks = [System.Collections.Generic.List[object]]::new()
$InternalLinkCount = 0
$ExternalReferences = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($File in $MarkdownFiles) {
    $Text = [System.IO.File]::ReadAllText(
        $File.Item.FullName,
        [System.Text.Encoding]::UTF8
    )

    $LinkMatches = [regex]::Matches(
        $Text,
        '(?<image>!)?\[[^\]]*\]\((?<target>[^)]+)\)'
    )

    foreach ($LinkMatch in $LinkMatches) {
        $Target = $LinkMatch.Groups["target"].Value.Trim()

        if ($Target.StartsWith("<") -and $Target.EndsWith(">")) {
            $Target = $Target.Substring(1, $Target.Length - 2)
        }

        if ($Target -match '^https?://') {
            [void]$ExternalReferences.Add($Target)
            continue
        }

        if (
            $Target.StartsWith("#") -or
            $Target -match '^mailto:'
        ) {
            continue
        }

        $TargetPath = ($Target -split '#', 2)[0]

        if ([string]::IsNullOrWhiteSpace($TargetPath)) {
            continue
        }

        $InternalLinkCount++

        $ResolvedPath = [System.IO.Path]::GetFullPath(
            (Join-Path $File.Item.DirectoryName $TargetPath)
        )

        if (-not (Test-Path -LiteralPath $ResolvedPath)) {
            $BrokenInternalLinks.Add(
                [pscustomobject]@{
                    File   = $File.RelativePath
                    Target = $Target
                }
            )
        }
    }
}

$TextFiles = @(
    $OfficialFiles |
        Where-Object {
            $_.Item.Extension -in @(
                ".md",
                ".kql",
                ".ps1",
                ".csv",
                ".txt",
                ".json"
            )
        }
)

$ScannableTextFiles = @($TextFiles)

$PrivacyPatterns = @(
    [pscustomobject]@{
        Label = "Known subscription identifier"
        Regex = ('9e65dd05-dd68-4506-' + '8305-60d391101235')
    },
    [pscustomobject]@{
        Label = "Personal cloud identity"
        Regex = (
            '(?i)daniel\.' + 'cloudpractice|' +
            'daniel' + 'cloudpractice|#' + 'EXT#'
        )
    },
    [pscustomobject]@{
        Label = "Private key"
        Regex = '(?i)-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----'
    },
    [pscustomobject]@{
        Label = "Bearer token"
        Regex = '(?i)authorization\s*:\s*bearer\s+'
    },
    [pscustomobject]@{
        Label = "Assigned secret or token"
        Regex = '(?i)(client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]'
    }
)

$PrivacyMatches = @(
    foreach ($File in $ScannableTextFiles) {
        $Text = [System.IO.File]::ReadAllText(
            $File.Item.FullName,
            [System.Text.Encoding]::UTF8
        )

        foreach ($Pattern in $PrivacyPatterns) {
            if ($Text -match $Pattern.Regex) {
                [pscustomobject]@{
                    File  = $File.RelativePath
                    Match = $Pattern.Label
                }
            }
        }
    }
)

$ProhibitedPublicLanguagePatterns = @(
    ('(?i)recr' + 'uit'),
    ('(?i)inter' + 'view'),
    ('(?i)employ' + 'er'),
    ('(?i)employ' + 'ment'),
    ('(?i)ca' + 'reer'),
    ('(?i)port' + 'folio'),
    ('(?i)candi' + 'date'),
    ('(?i)job[\s-]*' + 'ready'),
    ('(?i)r(?:e|' + [char]0x00E9 + ')su' +
        'm(?:e|' + [char]0x00E9 + ')'),
    ('(?i)curriculum\s+' + 'vitae'),
    ('(?i)show' + 'case'),
    ('(?i)cheat[\s-]*' + 'sheet')
)

$ProhibitedPublicLanguageMatches = @(
    foreach ($File in $ScannableTextFiles) {
        $Text = [System.IO.File]::ReadAllText(
            $File.Item.FullName,
            [System.Text.Encoding]::UTF8
        )

        foreach ($Pattern in $ProhibitedPublicLanguagePatterns) {
            if ($Text -match $Pattern) {
                [pscustomobject]@{
                    File    = $File.RelativePath
                    Pattern = $Pattern
                }
            }
        }
    }
)

$Utf8BomFiles = @(
    foreach ($File in $TextFiles) {
        $Bytes = [System.IO.File]::ReadAllBytes($File.Item.FullName)

        if (
            $Bytes.Length -ge 3 -and
            $Bytes[0] -eq 239 -and
            $Bytes[1] -eq 187 -and
            $Bytes[2] -eq 191
        ) {
            $File.RelativePath
        }
    }
)

$ReadmePath = Join-Path $RepositoryPath "README.md"
$ReadmeText = [System.IO.File]::ReadAllText(
    $ReadmePath,
    [System.Text.Encoding]::UTF8
)

$ExpectedReadmeStatus = "Complete $([char]0x2014) Milestones 0$([char]0x2013)8 validated"

$ReadmeFinalStatus = $ReadmeText.Contains($ExpectedReadmeStatus)

$ReadmeEvidenceCount = $ReadmeText.Contains(
    "| Evidence screenshots | 62 |"
)

$ExpectedStaleStatus = "In progress $([char]0x2014) Milestones 0$([char]0x2013)7"

$StaleReadmeLanguage = (
    $ReadmeText -match '(?i)Milestone 8 planned' -or
    $ReadmeText.Contains($ExpectedStaleStatus)
)

$ExpectedEvidenceHashes = @{
    "screenshots\m08-01-project1-rules-preserved.png" = (
        "99D4156C3E027A8BD669D2F258329171" +
        "EA3D1351FB645857371B1B6E22D2B236"
    )
    "screenshots\m08-02-final-powered-off-recovery-snapshot.png" = (
        "7CCC56BB9E7DD9AA8880ED37611E84D" +
        "3CBFE72156CA0E717BF1A1A94D8361B83"
    )
}

$EvidenceHashMismatches = @(
    foreach ($RelativePath in $ExpectedEvidenceHashes.Keys) {
        $FullPath = Join-Path $RepositoryPath $RelativePath
        $ActualHash = (
            Get-FileHash `
                -LiteralPath $FullPath `
                -Algorithm SHA256
        ).Hash

        if ($ActualHash -ne $ExpectedEvidenceHashes[$RelativePath]) {
            $RelativePath
        }
    }
)

$MarkdownCount = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".md" }
).Count

$CsvCount = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".csv" }
).Count

$KqlCount = @(
    $OfficialFiles |
        Where-Object { $_.Item.Extension -ieq ".kql" }
).Count

$PngCount = $PngFiles.Count
$PowerShellCount = $PowerShellFiles.Count

[pscustomobject]@{
    OfficialFileCount            = $OfficialFiles.Count
    ExpectedFileCount            = $ExpectedPaths.Count
    InventoryMatches             = $InventoryMatches
    MissingFileCount             = $MissingPaths.Count
    UnexpectedFileCount          = $UnexpectedPaths.Count
    EmptyFileCount               = $EmptyFiles.Count
    DuplicateContentGroups       = $DuplicateContentGroups.Count
    UnexpectedVariantFiles       = $UnexpectedVariantFiles.Count
    MarkdownFiles                = $MarkdownCount
    CsvFiles                     = $CsvCount
    KqlFiles                     = $KqlCount
    ScreenshotFiles              = $PngCount
    PowerShellFiles              = $PowerShellCount
    PowerShellParseFailures      = $PowerShellParseFailures.Count
    InvalidPngFiles              = $InvalidPngFiles.Count
    ScreenshotSequenceFailures   = $ScreenshotSequenceFailures.Count
    InternalLinkCount            = $InternalLinkCount
    BrokenInternalLinks          = $BrokenInternalLinks.Count
    UniqueExternalReferences     = $ExternalReferences.Count
    PrivacyMatches               = $PrivacyMatches.Count
    ProhibitedLanguageMatches    = $ProhibitedPublicLanguageMatches.Count
    Utf8BomFiles                 = $Utf8BomFiles.Count
    EvidenceHashMismatches       = $EvidenceHashMismatches.Count
    ReadmeFinalStatus            = $ReadmeFinalStatus
    ReadmeEvidenceCount          = $ReadmeEvidenceCount
    StaleReadmeLanguage          = $StaleReadmeLanguage
} | Format-List

$ValidationFailed = (
    $OfficialFiles.Count -ne 95 -or
    $ExpectedPaths.Count -ne 95 -or
    -not $InventoryMatches -or
    $MissingPaths.Count -ne 0 -or
    $UnexpectedPaths.Count -ne 0 -or
    $EmptyFiles.Count -ne 0 -or
    $DuplicateContentGroups.Count -ne 0 -or
    $UnexpectedVariantFiles.Count -ne 0 -or
    $MarkdownCount -ne 13 -or
    $CsvCount -ne 1 -or
    $KqlCount -ne 7 -or
    $PngCount -ne 62 -or
    $PowerShellCount -ne 12 -or
    $PowerShellParseFailures.Count -ne 0 -or
    $InvalidPngFiles.Count -ne 0 -or
    $ScreenshotSequenceFailures.Count -ne 0 -or
    $BrokenInternalLinks.Count -ne 0 -or
    $PrivacyMatches.Count -ne 0 -or
    $ProhibitedPublicLanguageMatches.Count -ne 0 -or
    $Utf8BomFiles.Count -ne 0 -or
    $EvidenceHashMismatches.Count -ne 0 -or
    -not $ReadmeFinalStatus -or
    -not $ReadmeEvidenceCount -or
    $StaleReadmeLanguage
)

if ($ValidationFailed) {
    if ($MissingPaths.Count -gt 0) {
        Write-Host "`nMissing files:" -ForegroundColor Yellow
        $MissingPaths
    }

    if ($UnexpectedPaths.Count -gt 0) {
        Write-Host "`nUnexpected files:" -ForegroundColor Yellow
        $UnexpectedPaths
    }

    if ($BrokenInternalLinks.Count -gt 0) {
        Write-Host "`nBroken internal links:" -ForegroundColor Yellow
        $BrokenInternalLinks | Format-Table -AutoSize
    }

    if ($PowerShellParseFailures.Count -gt 0) {
        Write-Host "`nPowerShell parse failures:" -ForegroundColor Yellow
        $PowerShellParseFailures | Format-Table -AutoSize
    }

    if ($PrivacyMatches.Count -gt 0) {
        Write-Host "`nPrivacy matches:" -ForegroundColor Yellow
        $PrivacyMatches | Format-Table -AutoSize
    }

    if ($ProhibitedPublicLanguageMatches.Count -gt 0) {
        Write-Host "`nProhibited public-language matches:" -ForegroundColor Yellow
        $ProhibitedPublicLanguageMatches | Format-Table -AutoSize
    }

    throw "Project 2 completed-repository validation failed."
}

Write-Host `
    "PASS: The completed 95-file Project 2 repository passed every local quality gate." `
    -ForegroundColor Green
