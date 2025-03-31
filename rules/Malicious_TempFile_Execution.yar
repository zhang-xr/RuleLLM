rule Malicious_TempFile_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects creation of a temporary file containing code to download and execute remote content"
        confidence = 90
        severity = 80

    strings:
        $tempfile_creation = "from tempfile import NamedTemporaryFile as _ffile"
        $urlopen_usage = "from urllib.request import urlopen as _uurlopen"
        $exec_usage = "exec(_uurlopen"
        $system_usage = "system(f\"start {_eexecutable.replace"

    condition:
        all of them
}