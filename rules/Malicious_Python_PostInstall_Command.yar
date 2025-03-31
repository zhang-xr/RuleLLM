rule Malicious_Python_PostInstall_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python post-install commands that download and execute scripts"
        confidence = 90
        severity = 85
    strings:
        $get_url = /get_url\s*=\s*lambda:\s*''\.join\(\[chr\(x\)\s*for\s*x\s*in\s*\[.*\]\]\)/
        $subprocess_run = /subprocess\.run\(/
        $curl_command = /curl\s+-\s*[sL]\s+/
        $bash_command = /bash\s+-\s*s\s+/
    condition:
        all of them
}