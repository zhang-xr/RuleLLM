rule ZIP_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the creation of a ZIP archive and its exfiltration"
        confidence = 90
        severity = 85
    strings:
        $zip_create = "ZipFile"
        $http_post = "requests.post"
    condition:
        all of them
}