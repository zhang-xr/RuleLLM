rule Python_DNS_Exfiltration_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts using DNS for data exfiltration"
        confidence = 90
        severity = 80
    strings:
        $dns_request = /def dns_request\(name, qtype=1, addr=\(['"][\d\.]+['"], \d+\), timeout=1\)/
        $custom_command = "def custom_command():"
        $hex_encoding = ".encode('utf-8').hex()"
        $install_hook = "class CustomInstallCommand(install)"
        $develop_hook = "class CustomDevelopCommand(develop)"
        $egg_info_hook = "class CustomEggInfoCommand(egg_info)"
    condition:
        filesize < 10KB and 
        all of them
}