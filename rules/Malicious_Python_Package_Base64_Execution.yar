rule Malicious_Python_Package_Base64_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that executes a base64-encoded payload during package installation."
        confidence = 90
        severity = 95

    strings:
        $base64_decode = "b64decode("
        $exec = "exec("
        $import_base64 = "__import__('base64')"

    condition:
        all of them and filesize < 10KB
}