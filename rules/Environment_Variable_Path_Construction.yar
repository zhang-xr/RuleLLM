rule Environment_Variable_Path_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects code using environment variables to construct malicious paths"
        confidence = 80
        severity = 85

    strings:
        $localappdata = "os.getenv('LOCALAPPDATA')" ascii wide
        $appdata = "os.getenv('APPDATA')" ascii wide
        $temp = "os.getenv('TEMP')" ascii wide
        $path_construction = /C:\\Users\\[^\\]+\\appdata\\roaming\\/ ascii wide

    condition:
        any of ($localappdata, $appdata, $temp) and 
        $path_construction
}