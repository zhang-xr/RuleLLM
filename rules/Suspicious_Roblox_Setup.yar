rule Suspicious_Roblox_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py configuration for Roblox stealer"
        confidence = 85
        severity = 80
    strings:
        $setup_import = "from setuptools import setup"
        $suspicious_packages = /"(browser_cookie3|discordwebhook|robloxpy)"/
        $empty_author = /author\s*=\s*""/
        $random_name = /name\s*=\s*'[a-z]{10,}'/
    condition:
        $setup_import and 
        2 of ($suspicious_packages) and 
        ($empty_author or $random_name)
}