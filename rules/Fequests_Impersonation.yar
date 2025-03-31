rule Fequests_Impersonation {
    meta:
        author = "RuleLLM"
        description = "Detects impersonation of the 'requests' library by the malicious 'fequests' package"
        confidence = 90
        severity = 80
    strings:
        $package_name = "fequests"
        $requests_description = "Python HTTP for Humans."
        $requests_url = "https://requests.readthedocs.io"
        $requests_author = "Kenneth Reitz"
    condition:
        $package_name and 
        all of ($requests_description, $requests_url, $requests_author)
}