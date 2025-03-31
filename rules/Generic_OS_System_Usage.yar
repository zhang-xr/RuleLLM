rule Generic_OS_System_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects generic use of os.system() in Python scripts, which is often indicative of malicious behavior."
        confidence = 80
        severity = 70

    strings:
        $os_system = "os.system"
        $shell_command = /os\.system\([\'\"][a-zA-Z0-9_\-\.\s]+[\'\"]\)/

    condition:
        all of ($os_system, $shell_command)
}