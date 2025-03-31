rule Malicious_Python_External_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that decode and execute base64-encoded external code."
        confidence = 90
        severity = 80

    strings:
        $base64_decode = /base64\.b64decode\([^)]+\)/
        $exec_call = /\bexec\([^)]+\)/
        $tempfile = /tempfile\.NamedTemporaryFile\(/
        $subprocess_call = /subprocess\.call\([^)]+\)/

    condition:
        any of ($base64_decode, $exec_call) and
        any of ($tempfile, $subprocess_call)
}