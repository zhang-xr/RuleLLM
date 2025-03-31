rule Python_Package_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages executing system commands during installation"
        confidence = 90
        severity = 80
    strings:
        $cmd1 = "import subprocess"
        $cmd2 = "subprocess.run("
        $cmd3 = /["']whoami["']/
        $cmd4 = "capture_output=True"
    condition:
        all of ($cmd1, $cmd2) and any of ($cmd3, $cmd4)
}