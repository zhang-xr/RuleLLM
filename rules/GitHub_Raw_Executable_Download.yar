rule GitHub_Raw_Executable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to download executables from GitHub raw URLs"
        confidence = 85
        severity = 80
    strings:
        $github_raw = "github.com" nocase wide
        $raw_path = "/raw/" nocase wide
        $exe_ext = ".exe" nocase wide
    condition:
        filesize < 10KB and
        $github_raw and $raw_path and $exe_ext
}