rule Discord_CDN_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects download attempts from Discord CDN with executable files"
        confidence = 85
        severity = 80
    strings:
        $discord_cdn = /https:\/\/cdn\.discordapp\.com\/attachments\/[0-9]+\/[0-9]+\/[^\s]+\.(exe|dll|scr)/ ascii wide
        $requests_get = "requests.get"
        $tempfile_write = "tmp_file.write(response.content)"
    condition:
        all of ($discord_cdn, $requests_get, $tempfile_write)
}