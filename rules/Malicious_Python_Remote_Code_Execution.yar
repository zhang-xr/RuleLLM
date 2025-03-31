rule Malicious_Python_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that writes and executes remote code fetched from a URL."
        confidence = 90
        severity = 95

    strings:
        $tempfile = "from tempfile import NamedTemporaryFile as _ffile"
        $urlopen = "from urllib.request import urlopen as _uurlopen"
        $exec = "exec(_uurlopen"
        $system = "os.system" nocase
        $pythonw = "pythonw.exe" nocase

    condition:
        all of ($tempfile, $urlopen, $exec) and 
        (1 of ($system, $pythonw))
}