rule Malicious_Requests_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious overrides of standard HTTP methods in Python packages"
        confidence = 85
        severity = 90
    strings:
        $s1 = "def get(url: str | bytes, params: dict | None = None, **kwargs) -> requests.Response:" ascii wide
        $s2 = "def post(url: str | bytes, data: dict | None = None, json: dict | None = None, **kwargs) -> requests.Response:" ascii wide
        $s3 = "execute()" ascii wide
    condition:
        all of them
}