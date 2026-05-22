$ErrorActionPreference = 'Stop'

try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

    $event = $raw | ConvertFrom-Json

    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    # CLI hook writes to its own log so it doesn't mix with the VS Code hook log.
    $logFile = Join-Path $logDir 'cli-tool-calls.jsonl'

    # Truncate very large result text to keep the log readable.
    $resultText = $null
    if ($event.toolResult -and $event.toolResult.textResultForLlm) {
        $resultText = [string]$event.toolResult.textResultForLlm
        if ($resultText.Length -gt 4000) {
            $resultText = $resultText.Substring(0, 4000) + '...[truncated]'
        }
    }

    $entry = [PSCustomObject]@{
        phase      = 'postToolUse'
        timestamp  = $event.timestamp
        time       = (Get-Date).ToString('o')
        cwd        = $event.cwd
        toolName   = $event.toolName
        toolArgs   = $event.toolArgs
        resultType = if ($event.toolResult) { $event.toolResult.resultType } else { $null }
        resultText = $resultText
    }

    Add-Content -Path $logFile -Value ($entry | ConvertTo-Json -Compress -Depth 6)
    exit 0
}
catch {
    try {
        $errLog = Join-Path $PSScriptRoot 'logs\hook-errors.log'
        $errDir = Split-Path $errLog -Parent
        if (-not (Test-Path $errDir)) { New-Item -ItemType Directory -Path $errDir | Out-Null }
        Add-Content -Path $errLog -Value "$(Get-Date -Format o) postToolUse: $($_.Exception.Message)"
    } catch { }
    exit 0
}
