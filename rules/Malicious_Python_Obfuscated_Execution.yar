rule Malicious_Python_Obfuscated_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that use base64 obfuscation and conditional checks before executing malicious code."
        confidence = 95
        severity = 85

    strings:
        $base64_decode = /base64\.b64decode\([^)]+\)/
        $exec_call = /\bexec\([^)]+\)/
        $os_exists = /os\.exists\([^)]+\)/
        $exit_call = /exit\(0\)/

    condition:
        ($base64_decode and $exec_call) and
        ($os_exists and $exit_call)
}