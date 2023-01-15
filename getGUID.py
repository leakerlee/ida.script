def getGUID(ea):
    data1 = int.from_bytes(ida_bytes.get_bytes(ea, 4), byteorder='little')

    ea += 4
    data2 = int.from_bytes(ida_bytes.get_bytes(ea, 2), byteorder='little')

    ea += 2
    data3 = int.from_bytes(ida_bytes.get_bytes(ea, 2), byteorder='little')

    ea += 2
    data4 = int.from_bytes(ida_bytes.get_bytes(ea, 2), byteorder='big')

    ea += 2
    data5 = int.from_bytes(ida_bytes.get_bytes(ea, 6), byteorder='big')

    return "%08X-%04X-%04X-%04X-%012X" % (data1, data2, data3, data4, data5)

print(getGUID(get_screen_ea()))

