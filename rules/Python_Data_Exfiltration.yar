rule Python_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that sends collected data to a remote server via an HTTPS POST request."
        confidence = "95"
        severity = "90"
    
    strings:
        $http_conn = "http.client.HTTPSConnection"
        $json_dumps = "json.dumps"
        $post_request = /conn\.request\("POST", "[^"]+", body=/
        $remote_url = "webhook.site"
    
    condition:
        all of them
}