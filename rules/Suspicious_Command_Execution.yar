rule Suspicious_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious command execution patterns"
        confidence = "85"
        severity = "75"
    
    strings:
        $platform_check = /platform\s*=\s*platform\.system\(\)/
        $python_cmd = /\b(python|python3)\b/
        $cmd_exec = /subprocess\.Popen\(\[.*?\]\)/
    
    condition:
        all of them
}