rule Packed_Executable
{
    meta:
        description = "Detects executables using packing techniques and obfuscation methods"
        author = "Security Team"
        date = "2026-05-30"
        severity = "high"

    strings:
        $unpack_sequence1 = "60 BE 45 23 11 00 8B FC F3 A5"
        $unpack_sequence2 = "55 8B EC 81 EC ?? ?? ?? ?? 8D ?? ?? ??"
        $decrypt_routine = "CryptDecrypt"
        $api_virtualalloc = "VirtualAlloc"
        $api_writeprocessmemory = "WriteProcessMemory"
        $api_setthreadcontext = "SetThreadContext"
        $api_createremotethread = "CreateRemoteThread"
        $network_connection = "192.168.33.45"

    condition:
        any of them
}