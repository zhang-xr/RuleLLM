rule Python_Stealthy_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to execute Python code using pythonw.exe to avoid console visibility"
        confidence = 85
        severity = 75

    strings:
        $pythonw_execution = /start {_eexecutable\.replace\('\.exe', 'w\.exe'\)}/
        $temp_file_creation = "from tempfile import NamedTemporaryFile as _ffile"

    condition:
        all of them
}