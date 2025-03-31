rule Python_Package_Exfiltration_1 {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with custom install commands that exfiltrate system information"
        confidence = 90
        severity = 80
    strings:
        $cmd1 = "subprocess.run([\"whoami\"], capture_output=True, text=True)"
        $cmd2 = "requests.post(url, data=data)"
        $cmd3 = "cmdclass={'install':"
        $url = "https://vigneshsb.me/test.php" nocase
    condition:
        all of them
}