rule ransomware_windows_HDDCryptorA
{
    meta:
        description = "The Very Basic HDDCryptor ransomware encrypts local harddisks as well as removable drives"
        reference = "https://youtu.be/LQnfjwAgCnE"
        author = "@fusionrace"

    strings:

        // unique strings
        $u1 = "You are Hacked" fullword nocase ascii wide  
        $u2 = "Your H.D.D Encrypted , Contact Us For Decryption Key" nocase ascii wide  
        $u3 = "start hard drive encryption" nocase ascii wide  
        $u4 = "Your hard drive is securely encrypted" nocase ascii wide  

        // generic strings
        $g1 = "Wipe All Passwords?" nocase ascii wide  
        $g2 = "SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config" nocase ascii wide  
        $g3 = "DiskCryptor" nocase ascii wide  
        $g4 = "dcinst.exe" fullword nocase ascii wide  
        $g5 = "dcrypt.exe" fullword nocase ascii wide  
        $g6 = "you can only use AES to encrypt the boot partition!" ascii nocase wide  

    condition:
        2 of ($u*) or 4 of ($g*) // At least 2 unique or at least 4 generic
}