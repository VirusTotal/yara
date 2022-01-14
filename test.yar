    import "pe"
    rule test
    {
        condition:
            for any rdata in (0..pe.number_of_sections-1): (
                for any idx in (0..pe.data_directories[12].size):(
                    for any i in (0..50): (
                        i == pe.sections[rdata].virtual_address+idx*8
                    )
                )
            )
    }
