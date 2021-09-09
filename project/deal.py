with open("payload.bin", "rb") as f:
    data = f.read()
ori_malloc = bytearray([0xE8, 0x58, 0x16, 0x00, 0x00])
patch_malloc = bytearray([0xCC, 0x58, 0x16, 0x00, 0x00])

result = bytearray(data).replace(ori_malloc, patch_malloc)
with open("result.bin", "wb") as f:
    f.write(result)

