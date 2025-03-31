rule Process_Manipulation_Pythonw {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to execute code using pythonw.exe"
        confidence = 85
        severity = 90

    strings:
        $pythonw = /pythonw\.exe/
        $system = "system"
        $start = "start"

    condition:
        all of ($pythonw, $system, $start)
}