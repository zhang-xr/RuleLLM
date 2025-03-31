rule Pythonw_TemporaryFile_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects execution of temporary files using pythonw.exe"
        confidence = 95
        severity = 85

    strings:
        $pythonw_exec = /start.*?pythonw\.exe.*?\".*?\.(py|tmp)\"/
        $tempfile_create = /_ffile\(delete=False\)/
        $exec_pattern = /exec\(.*?\)/

    condition:
        all of them
}