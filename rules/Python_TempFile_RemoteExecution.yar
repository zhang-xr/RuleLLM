rule Python_TempFile_RemoteExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code creating temporary files for remote code execution"
        confidence = "95"
        severity = "90"
    
    strings:
        $tempfile = "from tempfile import NamedTemporaryFile as"
        $urlopen = "from urllib.request import urlopen as"
        $exec = /exec\(.*?urlopen.*?read\(\)\)/
        $system = "system("
        $start_exec = /start.*?\.exe/
    
    condition:
        all of them and filesize < 10KB
}