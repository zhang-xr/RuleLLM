rule Setuptools_Shell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects shell command execution in setuptools install scripts"
        confidence = 85
        severity = 80

    strings:
        $os_popen = "os.popen"
        $os_system = "os.system"
        $shell_pattern = /(bash|sh|cmd|powershell)\s+-[cC]\s+['"].*['"]/

    condition:
        ($os_popen or $os_system) and $shell_pattern
}