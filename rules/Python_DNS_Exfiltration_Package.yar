rule Python_DNS_Exfiltration_Package {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup with DNS-based data exfiltration"
        confidence = "95"
        severity = "90"
    
    strings:
        $install_hook = "class CustomInstallCommand(install)"
        $develop_hook = "class CustomDevelopCommand(develop)"
        $egg_hook = "class CustomEggInfoCommand(egg_info)"
        $dns_func = "def dns_request(name, qtype=1, addr=('127.0.0.53', 53), timeout=1)"
        $data_collection = /['"](p|h|d|c)['"]\s*:\s*[^,}]+/
        $dns_hex = "hex_str = json_data.encode('utf-8').hex()"
        $chunking = "hex_list = [hex_str[(i * 60):(i + 1) * 60]"
        $dns_send = "s.sendto(request, addr)"
    
    condition:
        filesize < 10KB and
        4 of them and
        $dns_func and 
        ($install_hook or $develop_hook or $egg_hook) and
        $data_collection
}