rule Auto_SystemInfo_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects automatic system information collection and exfiltration on import"
        confidence = 85
        severity = 75
    strings:
        $collect_func = "collect_system_info()"
        $import_exec = /import\s+os\s*[\r\n]+from\s+urllib\.request\s+import\s+urlopen,\s+Request/
    condition:
        $collect_func and $import_exec
}