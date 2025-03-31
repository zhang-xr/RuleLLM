rule Suspicious_Exfiltration_Package {
    meta:
        author = "RuleLLM"
        description = "Detects packages with potential exfiltration capabilities"
        confidence = 85
        severity = 75
    strings:
        $setup = "from setuptools import setup, find_packages"
        $cookie = "browser_cookie3"
        $webhook = /(discordwebhook|requests)/
    condition:
        $setup and 
        ($cookie and $webhook) and 
        filesize < 10KB
}