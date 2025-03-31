rule Python_Base64_Obfuscated_Command {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded commands in Python code, commonly used for obfuscation in malicious scripts"
        confidence = 85
        severity = 75

    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/
        $lambda_chr = "lambda: ''.join([chr(x) for x in ["
        $subprocess_run = "subprocess.run"

    condition:
        $lambda_chr and $subprocess_run and $base64_pattern
}