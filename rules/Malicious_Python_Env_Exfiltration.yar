rule Malicious_Python_Env_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects environment variable exfiltration in setup.py"
        confidence = 90
        severity = 85

    strings:
        $env_collection = "env_data = {key: value for key, value in os.environ.items()}"
        $requests_post = "requests.post("
        $exfil_url = "http://gn7v017kvra8epx336tsoj42wt2kqce1.oastify.com"

    condition:
        $env_collection and $requests_post and $exfil_url
}