rule Suspicious_Python_File_Paths {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file paths defined in Python code, potentially for persistence or data exfiltration."
        confidence = 70
        severity = 60

    strings:
        $root_path = /os\.path\.join\(os\.path\.abspath\(os\.sep\), .*\)/
        $user_path = /os\.path\.join\(os\.path\.expanduser\(~\), .*\)/

    condition:
        any of ($root_path, $user_path)
}