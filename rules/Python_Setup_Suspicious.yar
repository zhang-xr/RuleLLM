rule Python_Setup_Suspicious {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with embedded malicious behavior"
        confidence = 90
        severity = 85

    strings:
        $setup_function = "setup("
        $subprocess_popen = "subprocess.Popen"
        $try_except = /try\s*:\s*\n\s*.*\s*\n\s*except\s*:\s*pass/

    condition:
        all of them
}