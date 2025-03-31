rule Python_SpecificShellCommand_ID {
    meta:
        author = "RuleLLM"
        description = "Detects Python code executing the 'id' command, which could indicate malicious behavior."
        confidence = 90
        severity = 80
    strings:
        $os_system = "os.system"
        $cmd_id = "'id'"
    condition:
        $os_system and $cmd_id
}