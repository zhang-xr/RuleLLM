rule Malicious_Python_Package_Startup_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects Python package that constructs a dynamic URL and persists a payload in the Windows startup folder"
        confidence = 90
        severity = 85

    strings:
        $dynamic_url = /https:\/\/cdn-.*\.split\s*\(\s*["']href="https:\/\/cdn-["']\s*\)/
        $startup_path = /os\.path\.join\s*\(\s*os\.environ\s*\[\s*["']APPDATA["']\s*\],\s*["']Microsoft["'],\s*["']Windows["'],\s*["']Start Menu["'],\s*["']Programs["'],\s*["']Startup["']/

    condition:
        all of them
}