rule Python_Suspicious_Setup_Keywords {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious keywords in Python setup files"
        confidence = 85
        severity = 75
    strings:
        $suspicious_keywords = /(typosquatting|pynalc|ffmpge|discrd)/ nocase
        $discord_url = /https?:\/\/(www\.)?discord\.gg\/[a-z0-9]+/ nocase
    condition:
        filesize < 2KB and
        2 of them
}