rule Python_ReverseShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to execute a reverse shell using bash."
        confidence = 95
        severity = 90

    strings:
        $reverse_shell = /bash\s+-c\s+['"]bash\s+-i\s+>&\s*\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\s+<&1['"]/
        $os_system = "os.system"
        $bash = "bash"

    condition:
        all of them
}