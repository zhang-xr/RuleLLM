rule Suspicious_Imports_And_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious imports and setup patterns in Python scripts"
        confidence = 85
        severity = 80

    strings:
        $requests_import = "from requests import"
        $getpass_import = "from getpass import"
        $os_import = "from os import"
        $socket_import = "from socket import"
        $setup_pattern = /setup\s*\(.*\)/

    condition:
        (any of ($requests_import, $getpass_import, $os_import, $socket_import)) and 
        $setup_pattern
}