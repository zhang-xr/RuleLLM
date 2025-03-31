rule Python_Reverse_Shell_Attempt {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to establish a reverse shell connection"
        confidence = 95
        severity = 100

    strings:
        $reverse_shell = /os\.system\s*\(\s*["']bash -c ['"]bash -i >& \/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/
        $os_system = "os.system"

    condition:
        $reverse_shell or ($os_system and /bash -i >& \/dev\/tcp\//)
}