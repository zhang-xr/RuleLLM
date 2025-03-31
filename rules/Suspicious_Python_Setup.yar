rule Suspicious_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts that may contain malicious code."
    strings:
        $setup_py = "setup.py"
    condition:
        $setup_py
}