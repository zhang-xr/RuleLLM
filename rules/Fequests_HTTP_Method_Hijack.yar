rule Fequests_HTTP_Method_Hijack {
    meta:
        author = "RuleLLM"
        description = "Detects hijacked HTTP methods in fequests package that execute malicious code"
        confidence = "90"
        severity = "85"
    
    strings:
        $method_names = /(get|post|put|patch|delete|head|options)/
        $execute_call = "execute()"
        $requests_import = "import requests"
    
    condition:
        $requests_import and 
        $execute_call and 
        3 of ($method_names)
}