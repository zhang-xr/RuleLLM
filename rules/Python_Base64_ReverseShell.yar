rule Python_Base64_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded Python reverse shell patterns"
        confidence = 90
        severity = 85
        
    strings:
        $base64_import = "import base64"
        $b64encode = "base64.b64encode"
        $b64decode = "base64 -d"
        $reverse_shell = /s\.connect\(\([\'\"].*[\'\"],\s*\d+\)\)/
        
    condition:
        all of ($base64_import, $b64encode) and
        any of ($b64decode, $reverse_shell)
}