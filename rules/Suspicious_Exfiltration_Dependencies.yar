rule Suspicious_Exfiltration_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects packages that require dependencies commonly used for data exfiltration"
        confidence = 80
        severity = 70
    strings:
        $discord_py = "discord.py"
        $aiohttp = "aiohttp"
        $requests = "requests"
    condition:
        all of them and filesize < 10KB
}