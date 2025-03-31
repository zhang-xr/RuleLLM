rule Obfuscated_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated remote code execution patterns"
        confidence = 88
        severity = 80

    strings:
        $urlopen_import = /from\s+urllib\.request\s+import\s+urlopen/
        $exec_pattern = /exec\(.*urlopen\(.*\)\.read\(\)\)/
        $system_usage = /system\(.*start.*pythonw?\.exe.*\)/

    condition:
        ($urlopen_import and $exec_pattern) or ($system_usage and $exec_pattern)
}