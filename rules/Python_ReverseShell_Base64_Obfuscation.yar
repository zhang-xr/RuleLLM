rule Python_ReverseShell_Base64_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded reverse shell commands in Python scripts"
        confidence = 85
        severity = 90

    strings:
        $base64_encode = /base64\.b64encode\(.*\.encode\(encoding="utf-8"\)\)/
        $base64_decode_exec = /os\.system\('echo %s\|base64 -d\|bash'/

    condition:
        all of them
}