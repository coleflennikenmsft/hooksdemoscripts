#requires -Version 5.1
# PreToolUse hook for VS Code GitHub Copilot Chat.
# - Blocks dangerous terminal commands.
# - Logs every tool invocation to logs/tool-calls.jsonl.
# Docs: https://code.visualstudio.com/docs/copilot/customization/hooks#_pretooluse

$ErrorActionPreference = 'Stop'

try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

    $event = $raw | ConvertFrom-Json

    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    $logFile = Join-Path $logDir 'tool-calls.jsonl'

    # VS Code passes tool_input as an already-parsed object (not a JSON string).
    $toolInput = $event.tool_input

    # Extract a candidate command string from typical shell-tool shapes.
    $command = $null
    if ($toolInput) {
        foreach ($prop in 'command', 'commandLine', 'cmd', 'script', 'input') {
            if ($toolInput.PSObject.Properties.Name -contains $prop -and $toolInput.$prop) {
                $command = [string]$toolInput.$prop
                break
            }
        }
    }

    # Patterns considered dangerous. Case-insensitive.
    $dangerPatterns = @(
        # Recursive/forced deletion of root, home, or wildcards
        '\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b.*(\s+/|\s+~|\s+\*|\s+\$HOME|\s+%USERPROFILE%)',
        '\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force[^\n]*(\\|/|\$HOME|\$env:USERPROFILE|C:\\)',
        '\bRemove-Item\b[^\n]*-Force[^\n]*-Recurse[^\n]*(\\|/|\$HOME|\$env:USERPROFILE|C:\\)',
        '\bdel\s+/[sfq/\s]*\s+[A-Za-z]:\\',
        '\brd\s+/s\s+/q\s+[A-Za-z]:\\',
        '\bFormat-Volume\b',
        '\bmkfs(\.|\s)',
        '\bformat\s+[A-Za-z]:',
        # Fork bomb
        ':\(\)\s*\{\s*:\|:&\s*\};:',
        # Privilege / system control
        '\bsudo\s+',
        '\bshutdown\b',
        '\breboot\b',
        '\bRestart-Computer\b',
        '\bStop-Computer\b',
        # Destructive git
        'git\s+push\s+(-f|--force|--force-with-lease)?\s*.*--no-verify',
        'git\s+push\s+--force(?!\-with\-lease)',
        'git\s+reset\s+--hard\s+(origin/|HEAD~|[a-f0-9]{7,})',
        'git\s+clean\s+-[fdx]{2,}',
        'git\s+checkout\s+--\s+\.',
        # SQL destruction
        '\bDROP\s+(TABLE|DATABASE|SCHEMA)\b',
        '\bTRUNCATE\s+TABLE\b',
        # Pipe-to-shell from network
        '(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)[^|]*\|\s*(sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)',
        # Disable security
        'Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true',
        'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off',
        # Credential exfiltration patterns
        '\bcat\s+.*\.ssh/id_',
        'Get-Content\s+.*\.ssh\\id_'
    )

    $matchedPattern = $null
    if ($command) {
        foreach ($p in $dangerPatterns) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch(
                    $command, $p,
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                $matchedPattern = $p
                break
            }
        }
    }

    $decision = if ($matchedPattern) { 'deny' } else { 'allow' }

    # Append log entry (JSON Lines).
    $entry = [PSCustomObject]@{
        phase           = 'PreToolUse'
        time            = (Get-Date).ToString('o')
        sessionId       = $event.session_id
        cwd             = $event.cwd
        toolName        = $event.tool_name
        command         = $command
        toolInput       = $toolInput
        decision        = $decision
        matchedPattern  = $matchedPattern
    }
    try {
        Add-Content -Path $logFile -Value ($entry | ConvertTo-Json -Compress -Depth 6)
    } catch { }

    if ($matchedPattern) {
        [PSCustomObject]@{
            hookSpecificOutput = [PSCustomObject]@{
                hookEventName           = 'PreToolUse'
                permissionDecision       = 'deny'
                permissionDecisionReason = "Blocked by local hook: command matched dangerous pattern /$matchedPattern/"
            }
        } | ConvertTo-Json -Compress -Depth 4
        exit 0
    }

    # Return an explicit allow decision using the documented PreToolUse output envelope.
    [PSCustomObject]@{
        hookSpecificOutput = [PSCustomObject]@{
            hookEventName      = 'PreToolUse'
            permissionDecision = 'allow'
        }
    } | ConvertTo-Json -Compress -Depth 4
    exit 0
}
catch {
    # On hook error, do NOT block the agent; just log to stderr for debugging.
    try {
        $errLog = Join-Path $PSScriptRoot 'logs\hook-errors.log'
        $errDir = Split-Path $errLog -Parent
        if (-not (Test-Path $errDir)) { New-Item -ItemType Directory -Path $errDir | Out-Null }
        Add-Content -Path $errLog -Value "$(Get-Date -Format o) preToolUse: $($_.Exception.Message)"
    } catch { }
    exit 0
}
