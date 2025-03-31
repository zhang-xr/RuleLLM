rule Data_Exfiltration_HTTP_GET {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP GET requests used for data exfiltration in Python scripts"
        confidence = 90
        severity = 80
    strings:
        $http_get = "requests.get("
        $params = "params="
        $sensitive_data = /(hostname|cwd|username)/
    condition:
        all of them and
        filesize < 10KB
}