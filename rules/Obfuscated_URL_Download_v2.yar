rule Obfuscated_URL_Download_v2 {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated URL construction and download in Python code"
        confidence = 95
        severity = 90
    strings:
        $lambda_url = /lambda:\s*''\.join\(\[chr\(x\)\s*for\s*x\s*in\s*\[.*\]\]\)/
        $curl = /curl\s+-\s*[sL]\s+/
        $bash = /bash\s+-\s*s\s+/
    condition:
        $lambda_url and ($curl or $bash)
}