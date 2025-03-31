rule python_setup_file_creation {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that create files during installation, a common technique for malicious payload delivery."
        confidence = 85
        severity = 75

    strings:
        $file_open = "open(" nocase wide ascii
        $write_mode = "'w'" nocase wide ascii
        $write_method = ".write(" nocase wide ascii
        $setup_func = "setup(" nocase wide ascii

    condition:
        all of ($file_open, $write_mode, $write_method) and $setup_func
}