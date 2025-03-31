rule Python_Package_Suspicious_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious execution patterns in Python packages"
        confidence = 95
        severity = 100
    strings:
        $exec1 = /os\.system\([^\)]+start\s+\w+\.exe/ ascii
        $exec2 = /set\s+__COMPACT_LAYER\s*=\s*RunAsInvoker/ ascii
        $exec3 = /\.write\(response\.content\)/ ascii
    condition:
        any of ($exec1, $exec2) and $exec3
}