rule Android_Image_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects image file exfiltration patterns"
        confidence = 85
        severity = 80
        reference = "Analyzed code segment"
    
    strings:
        $image_exts = /\.(jpg|jpeg|png)['"]/ ascii wide
        $open_file = "open(os.path.join" ascii wide
        $rb_mode = "'rb')" ascii wide
        $post_request = "session.post" ascii wide
    
    condition:
        all of ($image_exts, $open_file, $rb_mode, $post_request)
}