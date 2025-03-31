rule Python_Package_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that attempt to download and execute remote code"
        confidence = 90
        severity = 85
    strings:
        $urlopen = "urlopen as _uurlopen"
        $exec = "exec(_uurlopen"
        $start_exec = "start {_eexecutable.replace('.exe', 'w.exe')}"
    condition:
        all of ($urlopen, $exec, $start_exec)
}