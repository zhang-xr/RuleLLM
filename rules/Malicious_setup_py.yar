rule Malicious_setup_py {
    meta:
        author = "RuleLLM"
        description = "Detects misuse of setup.py files to execute malicious code"
        confidence = 80
        severity = 70

    strings:
        $setup = "setup("
        $subprocess = "subprocess.Popen" nocase
        $powershell = "powershell" nocase

    condition:
        all of them
}