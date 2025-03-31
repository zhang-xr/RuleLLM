rule Python_DataExfiltration_Base64_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information and exfiltrates it via HTTP using Base64 encoding"
        confidence = 90
        severity = 80
    strings:
        $ip_lookup = "requests.get('https://api.ipify.org')"
        $host_info = "os.uname()[1]"
        $path_info = "pathlib.Path(__file__).parent.absolute()"
        $base64_encode = "base64.b64encode"
        $http_exfil = "requests.get("
        $data_collection = /{\s*"ip":\s*\w+,\s*"host":\s*\w+,\s*"path":\s*\w+,\s*}/
    condition:
        all of them and 
        filesize < 10KB
}