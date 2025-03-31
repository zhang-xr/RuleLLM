rule Suspicious_Executable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects the download and execution of a specific executable (zwerve.exe) from a GitHub repository."
        confidence = 95
        severity = 90

    strings:
        $url = "https://github.com/holdthatcode/e/raw/main/zwerve.exe"
        $output_file = "zwerve.exe"
        $powershell = "powershell" nocase
        $subprocess = "subprocess.run"

    condition:
        all of them
}