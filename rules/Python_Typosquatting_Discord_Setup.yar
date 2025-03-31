rule Python_Typosquatting_Discord_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup patterns targeting Discord users"
        confidence = 90
        severity = 80
    strings:
        $pkg_name = "discrd" nocase
        $discord_invite = "discord.gg" nocase
        $typosquatting = "typosquatting" nocase
        $suspicious_email = /[a-z0-9]+@https?[a-z0-9\.]+/ nocase
        $suspicious_author = /[a-z0-9]{4} [a-z]{6}/ nocase
    condition:
        filesize < 2KB and
        all of them
}