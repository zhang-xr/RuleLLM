rule Suspicious_Python_Setup_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious metadata in Python setup.py files"
        confidence = 75
        severity = 80
    strings:
        $exploit_desc = /description\s*=\s*[\'\"].*exploit.*[\'\"]/
        $custom_install = "cmdclass={'install':"
        $suspicious_url = /url\s*=\s*[\'\"].*(github|gitlab).*[\'\"]/
    condition:
        any of them
}