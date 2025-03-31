rule Malicious_Python_Pastebin_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that downloads and executes code from Pastebin"
        confidence = 90
        severity = 95

    strings:
        $url = /https:\/\/pastebin\.pl\/view\/raw\/[a-f0-9]+/ nocase
        $exec = /exec\(compile\([^,]+,\s*[^,]+,\s*'exec'\)\)/ nocase
        $requests_get = /requests\.get\(/ nocase

    condition:
        all of them
}