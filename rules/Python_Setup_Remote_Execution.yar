rule Python_Setup_Remote_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects remote code execution patterns in Python setup scripts"
        confidence = 95
        severity = 90
    strings:
        $powershell = "powershell -Command"
        $start_process = "Start-Process"
        $subprocess = "subprocess.run"
        $http_url = /https?:\/\//
    condition:
        all of ($powershell, $start_process, $subprocess) and
        any of ($http_url)
}