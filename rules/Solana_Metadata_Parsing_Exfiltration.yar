rule Solana_Metadata_Parsing_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects metadata parsing that could be used for data exfiltration"
        confidence = 80
        severity = 70
    strings:
        $metadata_parsing = "getMetaData(data)"
        $base58_decode = "base58.b58decode(data)"
        $json_dumps = "json.dumps(metadata)"
        $http_request = "requests."
    condition:
        all of ($metadata_parsing, $base58_decode, $json_dumps) and
        any of ($http_request)
}