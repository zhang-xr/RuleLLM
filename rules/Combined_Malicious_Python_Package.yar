rule Combined_Malicious_Python_Package {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup scripts"
        confidence = 95
        severity = 90
    strings:
        $b64_decode_func = "base64.b64decode"
        $os_system = "os.system"
        $install_override = /class\s+\w+\(install\):/
        $develop_override = /class\s+\w+\(develop\):/
        $remote_url = /https?:\/\/[^\s]+\.exe/
        $file_write = /open\(.*,\s*['"]wb['"]\)\.write\(/
        $file_execute = /call\(.*\.exe\)/
    condition:
        3 of ($b64_decode_func, $os_system, $install_override, $develop_override, $remote_url, $file_write, $file_execute)
}