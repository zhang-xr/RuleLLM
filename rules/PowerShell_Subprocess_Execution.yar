rule PowerShell_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands executed via subprocess.run in Python scripts"
        confidence = 80
        severity = 75

    strings:
        $subprocess_run = /subprocess\.run\(\["powershell",\s*"-Command",\s*[^\]]+\]/
        $silent_flags = /-NoNewWindow\s+-Wait/

    condition:
        all of them and
        filesize < 10KB
}