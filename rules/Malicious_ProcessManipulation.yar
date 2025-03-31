rule Malicious_ProcessManipulation {
    meta:
        author = "RuleLLM"
        description = "Detects manipulation of processes to execute temporary files."
        confidence = 85
        severity = 80

    strings:
        $system_call = "system("
        $start_command = "start"
        $executable_replace = ".exe', 'w.exe')"

    condition:
        all of them and filesize < 10KB
}