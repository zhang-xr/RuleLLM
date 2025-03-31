rule Python_Typosquatting_Discord_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup.py patterns with typosquatting and Discord links"
        confidence = 85
        severity = 70
        
    strings:
        $setup = "from setuptools import setup"
        $discord_url = /https?:\/\/(www\.)?discord\.gg\/\w{6,}/
        $typosquatting = "typosquatting"
        $suspicious_email = /[\w\.]+@httpsdiscord\.gg[\w]+\.com/
        $random_author = /author\s*=\s*\"[\w\d]{4,}\s[\w\d]{4,}\"/
        
    condition:
        $setup and 
        (($discord_url and $suspicious_email) or 
         ($typosquatting and $random_author))
}