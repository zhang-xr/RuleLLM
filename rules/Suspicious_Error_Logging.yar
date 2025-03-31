rule Suspicious_Error_Logging {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious error logging to a file in Python scripts"
        confidence = 80
        severity = 70

    strings:
        $error_logging = "with open('/tmp/a', 'a') as f:"
        $error_write = "f.write(\"------- ? ? ? \" + str(e) + \"\\n\")"

    condition:
        all of them
}