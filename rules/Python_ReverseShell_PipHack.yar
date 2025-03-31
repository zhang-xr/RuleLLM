rule Python_ReverseShell_PipHack {
    meta:
        author = "RuleLLM"
        description = "Detects a malicious Python package that creates a reverse shell during installation"
        confidence = 90
        severity = 95

    strings:
        // Suspicious socket creation and connection
        $socket_connect = /socket\.connect\(\(.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},\s*\d{1,5}\)\)/
        $subprocess_popen = /subprocess\.Popen\(\[.*\]\s*,\s*stdout=subprocess\.PIPE/
        $os_dup2 = /os\.dup2\(.*\)/
        $cmd_exec = /\["cmd",\s*"\/K",\s*"cd.*"\]/
        $bash_exec = /\["\/bin\/bash",\s*"-i"\]/

    condition:
        // Match if the code contains socket connection and subprocess execution patterns
        $socket_connect and ($subprocess_popen or $os_dup2) and ($cmd_exec or $bash_exec)
}