rule Python_Base64_Exec_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using exec with base64-decoded payloads"
        confidence = 90
        severity = 85

    strings:
        $exec_base64 = /exec\(__import__\('base64'\)\.b64decode\([^)]+\)\)/
        $base64_import = "import base64"
        $exec_function = "exec("

    condition:
        any of ($exec_base64, $base64_import) and $exec_function
}