rule Python_Suspicious_InstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious install hooks in Python setup scripts"
        confidence = 90
        severity = 80

    strings:
        $install_class = /class \w+\(install\):/ nocase
        $system_call = "os.system" nocase
        $popen = "os.popen" nocase
        $bash = "bash -c" nocase

    condition:
        $install_class and any of ($system_call, $popen) and $bash
}