rule Obfuscated_Powershell {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated PowerShell commands in Python scripts"
        confidence = 90
        severity = 85

    strings:
        $powershell = "powershell"
        $encoded_command = /-EncodedCommand\s+[A-Za-z0-9+\/=]+/
        $hidden_window = /-WindowStyle\s+Hidden/

    condition:
        all of them
}