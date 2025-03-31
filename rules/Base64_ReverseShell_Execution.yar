rule Base64_ReverseShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded reverse shell execution in Python scripts"
        confidence = 85
        severity = 90

    strings:
        $base64_import = "import base64"
        $os_import = "import os"
        $base64_encode = /base64\.b64encode\(.*?\.encode\(/
        $base64_exec = /os\.system\(\'echo\s+%s\|base64\s+-d\|bash\'/

    condition:
        all of them
}