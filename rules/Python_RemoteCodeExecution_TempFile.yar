rule Python_RemoteCodeExecution_TempFile {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that create temporary files to download and execute remote code."
        confidence = 90
        severity = 95

    strings:
        $tempfile = "NamedTemporaryFile"
        $urlopen = "urlopen"
        $exec = "exec("
        $remote_exec = /exec\(_uurlopen\(['\"].+['\"]\)\.read\(\)\)/
        $start_command = /start\s+\S+\.exe\s+\S+\.tmp/

    condition:
        all of ($tempfile, $urlopen, $exec) and 
        (1 of ($remote_exec, $start_command))
}