rule Python_SilentExecution_Pythonw {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that attempt to execute code silently using pythonw.exe."
        confidence = 85
        severity = 80

    strings:
        $pythonw = "pythonw.exe"
        $system = "system"
        $start = "start"

    condition:
        all of ($pythonw, $system, $start) and 
        filesize < 10KB
}