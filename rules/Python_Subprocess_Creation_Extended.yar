rule Python_Subprocess_Creation_Extended {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts creating subprocesses or executing external commands"
        confidence = 80
        severity = 75

    strings:
        $subprocess = "subprocess"
        $os_system = "os.system"
        $run = "run"

    condition:
        any of ($subprocess, $os_system, $run)
}