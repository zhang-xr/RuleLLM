rule Malicious_Python_Suspicious_Package_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that installs multiple suspicious packages"
        confidence = 85
        severity = 80

    strings:
        $pip_install = /pip\.main\(\[\s*'install'\s*,\s*package\s*\]\)/ nocase
        $suspicious_packages = /(pycryptodome|pywinauto|pycaw|discord_webhook)/ nocase

    condition:
        $pip_install and $suspicious_packages
}