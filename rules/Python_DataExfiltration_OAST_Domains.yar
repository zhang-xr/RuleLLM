rule Python_DataExfiltration_OAST_Domains {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts making HTTP requests to suspicious OAST domains"
        confidence = 90
        severity = 80
    strings:
        $domain1 = /oast\.fun/ ascii wide
        $domain2 = /byted-dast\.com/ ascii wide
        $urllib = "urllib.request.urlopen" ascii wide
        $params = "urllib.parse.urlencode" ascii wide
    condition:
        all of them and filesize < 10KB
}