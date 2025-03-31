rule Malicious_Python_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to establish a reverse shell using bash"
        confidence = 90
        severity = 95

    strings:
        $reverse_shell = /bash -c 'bash -i >& \/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5} <&1'/
        $custom_install = "class CustomInstallCommand"
        $os_system = "os.system"

    condition:
        all of them
}