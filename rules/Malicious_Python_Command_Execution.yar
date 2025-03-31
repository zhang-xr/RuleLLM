rule Malicious_Python_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious command execution patterns in Python"
        confidence = 80
        severity = 75
    strings:
        $subprocess1 = "subprocess.run"
        $subprocess2 = "capture_output=True"
        $git_config = "git config user.email"
    condition:
        all of ($subprocess*) and $git_config and filesize < 10KB
}