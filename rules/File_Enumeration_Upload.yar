rule File_Enumeration_Upload {
    meta:
        author = "RuleLLM"
        description = "Detects code enumerating files and uploading them via HTTP POST"
        confidence = "85"
        severity = "80"
    strings:
        $os_listdir = "os.listdir"
        $file_upload = "self.session.post"
        $open_file = "open("
        $image_extensions1 = ".jpg"
        $image_extensions2 = ".jpeg"
        $image_extensions3 = ".png"
    condition:
        all of ($os_listdir, $file_upload, $open_file) and 
        (1 of ($image_extensions*))
}