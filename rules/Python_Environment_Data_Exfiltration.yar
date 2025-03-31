rule Python_Environment_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects and exfiltrates environment variables"
        confidence = 92
        severity = 85
    strings:
        $environ_dict = "dict(os.environ)"
        $urlencode = "urllib.parse.urlencode"
        $request = "urllib.request.Request"
        $urlopen = "urllib.request.urlopen"
        $http_post = /\.Request\([^,]+,\s*data=/
    condition:
        $environ_dict and 
        ($urlencode or $request or $urlopen) and 
        $http_post
}