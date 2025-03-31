rule Malicious_Pythonw_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uses pythonw.exe to execute scripts stealthily."
        confidence = 80
        severity = 85

    strings:
        $pythonw = "pythonw.exe" nocase
        $system = "os.system" nocase
        $exec = "exec("

    condition:
        all of ($pythonw, $system, $exec)
}