rule Python_Home_Directory_File_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects file creation in user's home directory with suspicious patterns"
        confidence = 80
        severity = 85
    strings:
        $os_path_join = "os.path.join(" ascii wide
        $expanduser = "os.path.expanduser(" ascii wide
        $file_write = /with\s+open\([^,]+,\s*['"]w['"]/ ascii wide
        $suspicious_filename = /(WindowsDefender\.py|malware\.py|payload\.py)/ ascii wide
    condition:
        all of ($os_path_join, $expanduser, $file_write) and $suspicious_filename
}