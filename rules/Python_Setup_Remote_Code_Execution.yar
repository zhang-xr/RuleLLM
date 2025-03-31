rule Python_Setup_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that download and execute remote code using urlopen and exec."
        confidence = 90
        severity = 95

    strings:
        $urlopen = "urlopen"
        $exec = "exec"
        $tempfile = "NamedTemporaryFile"
        $system = "system"
        $setup = "setup("
        $remote_url = /https?:\/\/[^\s"]+/ ascii wide

    condition:
        all of ($urlopen, $exec, $tempfile, $system, $setup) and 
        $remote_url and 
        filesize < 2KB
}