rule Exfiltration_Over_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests used for data exfiltration in Python scripts"
        confidence = "95"
        severity = "90"
    
    strings:
        $requests_import = "import requests"
        $get_request = "requests.get("
        $params_dict = "{'hostname':"
    
    condition:
        all of them
}