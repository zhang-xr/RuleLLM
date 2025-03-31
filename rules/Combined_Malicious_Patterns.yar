rule Combined_Malicious_Patterns {
    meta:
        author = "RuleLLM"
        description = "Detects combined patterns of temporary file creation, URL execution, and process manipulation."
        confidence = 95
        severity = 90

    strings:
        $tempfile_create = "NamedTemporaryFile(delete=False)"
        $urlopen_exec = /urllib\.request\.urlopen\(.*\)\.read\(\)/
        $exec_call = "exec("
        $system_call = "system("
        $start_command = "start"
        $executable_replace = ".exe', 'w.exe')"

    condition:
        3 of them and filesize < 10KB
}