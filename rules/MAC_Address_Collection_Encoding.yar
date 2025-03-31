rule MAC_Address_Collection_Encoding {
    meta:
        author = "RuleLLM"
        description = "Detects collection and encoding of MAC addresses"
        confidence = 85
        severity = 80

    strings:
        $getmac_cmd = "getmac" nocase
        $ifconfig_cmd = "ifconfig" nocase
        $mac_check = "Physical" nocase
        $ether_check = "ether" nocase
        $base64_encode = "base64.b64encode("

    condition:
        ($getmac_cmd or $ifconfig_cmd) and ($mac_check or $ether_check) and $base64_encode
}