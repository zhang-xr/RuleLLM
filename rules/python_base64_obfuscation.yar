rule python_base64_obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded strings in Python code, commonly used for obfuscation"
        confidence = 80
        severity = 85

    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{10,}={0,2}/ // Regex for Base64 strings

    condition:
        $base64_pattern and filesize < 10KB
}