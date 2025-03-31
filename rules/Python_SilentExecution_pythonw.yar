rule Python_SilentExecution_pythonw {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to execute Python scripts silently using pythonw.exe"
        confidence = 85
        severity = 80

    strings:
        $pythonw = /pythonw\.exe/ ascii
        $system = "system(" ascii
        $start = "start" ascii

    condition:
        all of ($pythonw, $system, $start)
}