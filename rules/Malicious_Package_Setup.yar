rule Malicious_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup scripts"
        confidence = 90
        severity = 85

    strings:
        $install_override = /class\s+\w+\(install\):/
        $exec_payload = /exec\(__import__\('base64'\)\.b64decode\([^)]+\)\)/
        $setup_function = "setup("

    condition:
        $install_override and $exec_payload and $setup_function
}