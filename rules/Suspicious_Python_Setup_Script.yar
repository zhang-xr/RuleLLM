rule Suspicious_Python_Setup_Script {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts with custom install commands and unusual dependencies."
        confidence = 85
        severity = 80

    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $discord_dep = /install_requires\s*=\s*\[[^\]]*["']discord\.py["']/
        $aiohttp_dep = /install_requires\s*=\s*\[[^\]]*["']aiohttp["']/
        $socket_import = "import socket"

    condition:
        $custom_install and
        (1 of ($discord_dep, $aiohttp_dep)) and
        $socket_import
}