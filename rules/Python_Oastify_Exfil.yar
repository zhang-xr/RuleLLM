rule Python_Oastify_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects exfiltration attempts to oastify.com domains"
        confidence = 95
        severity = 90
    strings:
        $oastify_domain = /[a-z0-9]{16,32}\.oastify\.com/
        $http_request = "requests.get"
        $params_key = "params="
    condition:
        all of them and
        filesize < 10KB
}