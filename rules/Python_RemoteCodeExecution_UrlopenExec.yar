rule Python_RemoteCodeExecution_UrlopenExec {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that download and execute code from a remote URL using urllib.request.urlopen and exec."
        confidence = 90
        severity = 95

    strings:
        $urlopen = "urlopen"
        $exec = "exec"
        $urllib = "urllib.request"
        $tempfile = "NamedTemporaryFile"
        $system = "system"

    condition:
        all of ($urlopen, $exec, $urllib) and 
        (1 of ($tempfile, $system)) and 
        filesize < 10KB
}