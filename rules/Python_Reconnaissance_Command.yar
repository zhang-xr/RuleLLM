rule Python_Reconnaissance_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python code executing reconnaissance commands like directory listing."
        confidence = 85
        severity = 70

    strings:
        $os_popen = "os.popen"
        $ls_command = /os\.popen\(['"]ls\s+\/['"]\)\.read\(\)/

    condition:
        any of them
}