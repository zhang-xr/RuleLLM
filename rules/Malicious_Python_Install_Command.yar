rule Malicious_Python_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects a custom Python install command that executes subprocess commands and sends data to a remote server"
        confidence = 90
        severity = 80

    strings:
        $install_class = /class\s+\w+\(install\):/
        $subprocess_run = /subprocess\.run\(\[.*\]\,.*capture_output\s*\=\s*True/
        $requests_post = /requests\.post\(.*\,.*data\s*\=\s*\{.*\}/

    condition:
        all of them
}