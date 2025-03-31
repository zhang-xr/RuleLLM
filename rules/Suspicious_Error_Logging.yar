rule Suspicious_Error_Logging {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious error logging to /tmp/a in Python scripts"
        confidence = 80
        severity = 70

    strings:
        $error_logging = /with open\('\/tmp\/a', 'a'\) as f:/
        $exception_handling = "except Exception as e:"

    condition:
        filesize < 10KB and
        all of them
}