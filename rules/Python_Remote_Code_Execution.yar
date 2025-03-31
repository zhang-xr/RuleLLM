rule Python_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that downloads and executes remote code using urllib.request and system calls."
        confidence = 90
        severity = 95

    strings:
        $urlopen = "urlopen(Request(url="
        $exec = "exec(urlopen"
        $system = "system(f\"start {_eexecutable.replace('.exe', 'w.exe')}"
        $tempfile = "NamedTemporaryFile"

    condition:
        all of them
}