# PostToolUse hook for VS Code GitHub Copilot Chat.
# Logs the result of every tool invocation to logs/tool-calls.jsonl.
# Docs: https://code.visualstudio.com/docs/copilot/customization/hooks#_posttooluse

$ErrorActionPreference = 'Stop'

try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

    $event = $raw | ConvertFrom-Json

    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    $logFile = Join-Path $logDir 'tool-calls.jsonl'

    # VS Code passes the tool result as `tool_response` (object, already parsed).
    $toolResponse = $event.tool_response

    # Try to surface a human-readable result string from common shapes,
    # then truncate to keep the log readable.
    $resultText = $null
    if ($toolResponse) {
        foreach ($prop in 'textResultForLlm', 'text', 'output', 'stdout', 'content') {
            if ($toolResponse.PSObject.Properties.Name -contains $prop -and $toolResponse.$prop) {
                $resultText = [string]$toolResponse.$prop
                break
            }
        }
        if (-not $resultText) {
            try { $resultText = ($toolResponse | ConvertTo-Json -Compress -Depth 6) } catch { }
        }
    }
    if ($resultText -and $resultText.Length -gt 4000) {
        $resultText = $resultText.Substring(0, 4000) + '...[truncated]'
    }

    $entry = [PSCustomObject]@{
        phase      = 'PostToolUse'
        time       = (Get-Date).ToString('o')
        sessionId  = $event.session_id
        cwd        = $event.cwd
        toolName   = $event.tool_name
        toolInput  = $event.tool_input
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
        Add-Content -Path $errLog -Value "$(Get-Date -Format o) PostToolUse: $($_.Exception.Message)"
    } catch { }
    exit 0
}
