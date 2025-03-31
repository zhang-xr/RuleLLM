rule Suspicious_Python_Setup_Trojan {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts that may contain trojanized code"
        confidence = 80
        severity = 75

    strings:
        $setup_function = "setup("
        $subprocess_popen = "subprocess.Popen("
        $powershell_cmd = "powershell"

    condition:
        $setup_function and $subprocess_popen and $powershell_cmd
}