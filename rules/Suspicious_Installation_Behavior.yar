rule Suspicious_Installation_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious behavior during Python package installation"
        confidence = "80"
        severity = "70"
    
    strings:
        $sleep = "sleep"
        $print_install = "Installation completed[OK]"
        $download_finished = "Download finished..."
    
    condition:
        all of them
}