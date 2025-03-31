rule Hidden_Powershell_Download {
    meta:
        author = "RuleLLM"
        description = "Detects hidden PowerShell commands used to download and execute files. This"
    strings:
        $s1 = "powershell" nocase
        $s2 = "hidden" nocase
        $s3 = "download" nocase
    condition:
        all of them
}