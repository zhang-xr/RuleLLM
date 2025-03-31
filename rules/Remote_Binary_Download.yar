rule Remote_Binary_Download {
    meta:
        author = "RuleLLM"
        description = "Detects the download of a binary from a remote URL"
        confidence = "80"
        severity = "80"
    
    strings:
        $url_dict = "url = {"
        $requests_get = "requests.get(url)"
        $binary_write = "with open(binary_path, 'wb') as f:"
        $exec_permission = "os.chmod(binary_path, stat.S_IREAD | stat.S_IEXEC"
    
    condition:
        all of them
}