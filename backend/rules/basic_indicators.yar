rule Heuristic_PowerShell_Download_Decode_Execute
{
    meta:
        description = "PowerShell contains download, decode, and execution indicators; this is heuristic, not a malware verdict."
        recommendation = "อย่าเปิดไฟล์ทันที ตรวจแหล่งที่มาและบริบทโดยผู้ดูแลระบบ และยืนยันผลด้วยเครื่องมือป้องกันไวรัสที่เชื่อถือได้"

    strings:
        $download1 = "DownloadString" nocase ascii wide
        $download2 = "DownloadFile" nocase ascii wide
        $decode1 = "FromBase64String" nocase ascii wide
        $decode2 = "-EncodedCommand" nocase ascii wide
        $execute1 = "Invoke-Expression" nocase ascii wide
        $execute2 = "IEX" nocase ascii wide

    condition:
        1 of ($download*) and 1 of ($decode*) and 1 of ($execute*)
}

rule Heuristic_JavaScript_Decode_Dynamic_Execute
{
    meta:
        description = "JavaScript contains encoded-data decoding and dynamic code execution indicators; this is heuristic, not a malware verdict."
        recommendation = "ตรวจสอบแหล่งที่มาของสคริปต์และเหตุผลที่ต้องถอดรหัสแล้วประมวลผลโค้ดแบบไดนามิก หลีกเลี่ยง eval หรือ Function กับข้อมูลที่ไม่น่าเชื่อถือ"

    strings:
        $decode1 = "atob(" nocase ascii wide
        $decode2 = "Buffer.from(" nocase ascii wide
        $execute1 = "eval(" nocase ascii wide
        $execute2 = "new Function(" nocase ascii wide

    condition:
        1 of ($decode*) and 1 of ($execute*)
}

rule Malware_EICAR_Test_File
{
    meta:
        description = "Standard Antivirus Test Signature (EICAR) used for testing detection capability."
        severity = "high"
        recommendation = "ไฟล์ทดสอบไวรัสมาตรฐาน EICAR ยืนยันว่าเครื่องยนต์ตรวจจับทำงานได้อย่างถูกต้อง"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar
}

rule Heuristic_Ransomware_Note_Indicators
{
    meta:
        description = "File contains ransomware extortion and decryption demand indicators."
        severity = "high"
        recommendation = "ตรวจพบข้อความเรียกค่าไถ่หรือข่มขู่เข้ารหัสข้อมูล แยกเครื่องออกจากเครือข่ายทันทีและตรวจสอบการสำรองข้อมูล"

    strings:
        $ransom1 = "all your files have been encrypted" nocase ascii wide
        $ransom2 = "your personal files are encrypted" nocase ascii wide
        $ransom3 = "send bitcoin to" nocase ascii wide
        $ransom4 = "pay ransom" nocase ascii wide
        $ransom5 = "to decrypt your files" nocase ascii wide
        $ransom6 = "how to decrypt" nocase ascii wide

    condition:
        2 of ($ransom*)
}

rule Heuristic_Webshell_PHP_Eval
{
    meta:
        description = "PHP script with obfuscated command execution / webshell backdoor pattern."
        severity = "high"
        recommendation = "พบรูปแบบ Webshell หรือคำสั่งลอบรันโค้ดระยะไกล ลบไฟล์หรือกักกันเพื่อตรวจสอบแหล่งที่มา"

    strings:
        $php = "<?php" nocase ascii
        $eval = "eval(" nocase ascii
        $b64 = "base64_decode(" nocase ascii
        $post = "$_POST[" ascii
        $req = "$_REQUEST[" ascii
        $pass = "passthru(" nocase ascii
        $sys = "system(" nocase ascii
        $shell = "shell_exec(" nocase ascii

    condition:
        $php and ($eval or $pass or $sys or $shell) and ($b64 or $post or $req)
}

