rule Malicious_Python_Setup_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py files that override the install class to execute encrypted payloads."
        confidence = 95
        severity = 90
    strings:
        $class_override = /class\s+\w+\(install\):/
        $exec_decrypt = /exec\(Fernet\(.+?\)\.decrypt\(.+?\)\)/
        $os_check = /if\s+os\.name\s*==\s*["']nt["']/
    condition:
        all of them
}