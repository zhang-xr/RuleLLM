rule Python_Malicious_Setup_Base64_Execution_v2 {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with base64 encoded payload execution in custom install commands"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstallCommand(install):"
        $base64_exec = /exec\(base64\.b64decode\([\s\S]{100,}\)\)/
        $try_except = "try:"
    condition:
        all of them and filesize < 10KB
}