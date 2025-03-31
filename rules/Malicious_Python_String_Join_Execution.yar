rule Malicious_Python_String_Join_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string joining and execution"
        confidence = 85
        severity = 80

    strings:
        $join_pattern = /"".join\s*\(/
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/
        $exec_pattern = /exec\s*\(.*\)/

    condition:
        $join_pattern and 
        any of ($chr_pattern, $exec_pattern)
}