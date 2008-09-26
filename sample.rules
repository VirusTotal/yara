
rule UPX : Packer
{
    strings: 
        $a = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8}

    condition:
        $a at entrypoint
        
}

