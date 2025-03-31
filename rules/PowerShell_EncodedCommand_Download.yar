rule PowerShell_EncodedCommand_Download {
    meta:
        author = "RuleLLM"
        description = "Detects encoded PowerShell commands used for downloading files"
        confidence = 90
        severity = 85
        
    strings:
        $powershell = "powershell" nocase
        $encoded = "-EncodedCommand" nocase
        $invoke = /Invoke[\-\s]*(WebRequest|Expression)/ nocase
        $uri = /-Uri\s+["'][^"']+["']/ nocase
        $outfile = /-OutFile\s+["'][^"']+["']/ nocase
        
    condition:
        all of ($powershell, $encoded) and
        any of ($invoke, $uri, $outfile)
}