rule Python_ModifiedInterpreterExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that attempt to execute code using a modified interpreter (e.g., pythonw.exe)."
        confidence = 80
        severity = 85

    strings:
        $executable = "executable"
        $replace = ".replace('.exe', 'w.exe')"
        $start_command = /start\s+\S+\.exe\s+\S+\.tmp/

    condition:
        all of ($executable, $replace) and 
        $start_command
}