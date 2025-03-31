rule Malicious_Base64_Python_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded Python code execution using builtins.exec"
        confidence = 95
        severity = 90

    strings:
        $base64_exec = /__import__\s*\(\s*['"]builtins['"]\s*\)\s*\.\s*exec\s*\(\s*__import__\s*\(\s*['"]builtins['"]\s*\)\s*\.\s*compile\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)\s*\.\s*b64decode\s*\(.*\)\s*,\s*['"]<string>['"]\s*,\s*['"]exec['"]\s*\)\s*\)/
        $base64_import = "__import__('base64').b64decode("
        $exec_import = "__import__('builtins').exec"

    condition:
        all of them
}