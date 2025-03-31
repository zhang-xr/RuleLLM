rule Remote_Code_Execution_Subprocess {
    meta:
        author = "RuleLLM"
        description = "Detects remote code execution via subprocess.call"
        confidence = 75
        severity = 80
    strings:
        $subprocess_call = "subprocess.call"
        $shell_cmd = "python3 /tmp/pytmp.py"
    condition:
        all of them
}