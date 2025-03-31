rule Malicious_Python_Obfuscation_Lambda {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using lambda functions and obfuscation techniques commonly found in malware."
        confidence = 90
        severity = 85

    strings:
        $lambda_obfuscation = /lambda\s+\w+\s*:/
        $base64_import = "import base64"
        $codecs_import = "import codecs"
        $zlib_import = "import zlib"
        $eval_exec = /eval\s*\(|exec\s*\(/

    condition:
        all of ($lambda_obfuscation, $base64_import, $codecs_import, $zlib_import) and any of ($eval_exec)
}