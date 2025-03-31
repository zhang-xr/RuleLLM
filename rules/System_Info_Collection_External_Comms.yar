rule System_Info_Collection_External_Comms {
    meta:
        author = "RuleLLM"
        description = "Detects combination of system information collection and external communication"
        confidence = 95
        severity = 85
    strings:
        $hostname_collection = "socket.gethostname()"
        $path_collection = "os.getcwd()"
        $external_comms = /requests\.(post|get)\([\s\S]*https?:/
        $data_dict = /\{\s*[\"'](hostname|current_path)[\"']:/
    condition:
        ($hostname_collection or $path_collection) and
        $external_comms and
        $data_dict
}