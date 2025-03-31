rule Python_Typosquatting_Selenium_Discord {
    meta:
        author = "RuleLLM"
        description = "Detects Python typosquatting attempt targeting Selenium with Discord-related social engineering"
        confidence = 90
        severity = 80
        reference = "Potential malicious package distribution via Discord"
    
    strings:
        $name = "selenim" nocase
        $discord_url = "https://discord.gg/" wide
        $email = /httpsdiscord\.gg[^\s@]+@[^\s@]+\.[^\s@]+/ wide
        $keywords = "pynacl discord voice mp3 ffmpge typosquatting sound pynalc" wide
    
    condition:
        all of them and 
        filesize < 2KB
}