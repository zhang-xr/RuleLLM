rule Obfuscated_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated remote code execution patterns in Python scripts"
        confidence = 85
        severity = 85
    strings:
        $urlopen_obfuscated = /_uurlopen\s*\(\s*['\"].+['\"]\s*\)/
        $exec_obfuscated = /exec\s*\(\s*_uurlopen\s*\(/
        $system_obfuscated = /_ssystem\s*\(\s*f\s*['\"].+['\"]/
    condition:
        any of ($urlopen_obfuscated, $exec_obfuscated, $system_obfuscated)
}