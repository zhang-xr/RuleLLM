rule Command_Execution_os_system {
    meta:
        author = "RuleLLM"
        description = "Detects use of os.system to execute shell commands"
        confidence = 80
        severity = 70

    strings:
        $os_system = "os.system("
        $curl_command = /curl\s+/

    condition:
        all of them
}