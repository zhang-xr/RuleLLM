rule Malicious_Python_Setup_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with suspicious dependencies commonly used in malicious packages."
        confidence = 80
        severity = 70
    strings:
        $discord = "discord"
        $aiohttp = "aiohttp"
        $sockets = "sockets"
        $setup = "setup("
    condition:
        all of ($discord, $aiohttp, $sockets) and $setup
}