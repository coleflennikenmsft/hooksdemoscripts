#requires -Version 5.1
# Pre-tool-use hook for GitHub Copilot.
# - Blocks dangerous terminal commands.
# - Logs every tool invocation to logs/tool-calls.jsonl.
# Docs: https://docs.github.com/en/copilot/reference/hooks-configuration

$ErrorActionPreference = 'Stop'
try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

    $event = $raw | ConvertFrom-Json

    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    # CLI hook writes to its own log so it doesn't mix with the VS Code hook log.
    $logFile = Join-Path $logDir 'cli-tool-calls.jsonl'

    # toolArgs may arrive as a JSON-encoded string (CLI shell-tool shape) or as an
    # already-parsed object. Normalize to an object when possible, and keep the raw
    # JSON text as a fallback haystack for pattern matching.
    $toolArgsRaw = $null
    $toolArgsObj = $null
    if ($null -ne $event.toolArgs) {
        if ($event.toolArgs -is [string]) {
            $toolArgsRaw = [string]$event.toolArgs
            try { $toolArgsObj = $toolArgsRaw | ConvertFrom-Json } catch { $toolArgsObj = $null }
        } else {
            $toolArgsObj = $event.toolArgs
            try { $toolArgsRaw = ($toolArgsObj | ConvertTo-Json -Compress -Depth 10) } catch { $toolArgsRaw = $null }
        }
    }

    # Extract a candidate command string from typical tool shapes (shell + SQL + scripts).
    $command = $null
    if ($toolArgsObj -and $toolArgsObj.PSObject) {
        foreach ($prop in 'command', 'commandLine', 'cmd', 'script', 'input', 'query', 'sql', 'statement') {
            if ($toolArgsObj.PSObject.Properties.Name -contains $prop -and $toolArgsObj.$prop) {
                $command = [string]$toolArgsObj.$prop
                break
            }
        }
    }

    # Always also scan the raw toolArgs JSON so patterns catch dangerous content in
    # less-common arg shapes (different field names, nested objects, etc.).
    $haystack = @($command, $toolArgsRaw) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Out-String

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
    if ($haystack) {
        foreach ($p in $dangerPatterns) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch(
                    $haystack, $p,
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                $matchedPattern = $p
                break
            }
        }
    }

    $decision = if ($matchedPattern) { 'deny' } else { 'allow' }

    # Append log entry (JSON Lines).
    $entry = [PSCustomObject]@{
        phase           = 'preToolUse'
        timestamp       = $event.timestamp
        time            = (Get-Date).ToString('o')
        cwd             = $event.cwd
        toolName        = $event.toolName
        command         = $command
        toolArgs        = $event.toolArgs
        decision        = $decision
        matchedPattern  = $matchedPattern
    }
    try {
        Add-Content -Path $logFile -Value ($entry | ConvertTo-Json -Compress -Depth 6)
    } catch { }

    if ($matchedPattern) {
        # CLI preToolUse decision control: bare JSON object with permissionDecision.
        [PSCustomObject]@{
            permissionDecision       = 'deny'
            permissionDecisionReason = "Blocked by local hook: command matched dangerous pattern /$matchedPattern/"
        } | ConvertTo-Json -Compress -Depth 4
        exit 0
    }

    # Empty output lets the CLI use default behavior (allow / fall through to normal permission flow).
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
