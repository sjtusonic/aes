from Crypto.Cipher import AES


class Aescrypt():
    def __init__(self, key, model, iv):
        print('CALL init %s,%s,%s' % (key, model, iv))
        self.key = self.add_16(key.encode('utf-8'))
        # self.model = str(model).encode('utf-8')
        self.model = model
        print('DBG self.model=', self.model)
        self.iv = iv
        # self.iv = str(iv).encode('utf-8')
        self.aes = None

    def add_16(self, par):
        if type(par) == str:
            par = par.encode()
        while len(par) % 16 != 0:
            par += b'\x00'
        return par

    def aesencrypt(self, text):
        text = self.add_16(text)
        print('CALL aesencrypt:',text)
        print('dbg AES.MODE_CBC:', AES.MODE_CBC)
        print('dbg AES.MODE_ECB:', AES.MODE_ECB)
        if self.model == AES.MODE_CBC:
            self.aes = AES.new(self.key, self.model, self.iv)
        elif self.model == AES.MODE_ECB:
            self.aes = AES.new(self.key, self.model)
        else:
            self.aes = AES.new("Default_Key", "Default_Model")
            assert (False)
        self.encrypt_text = self.aes.encrypt(text)
        # self.encrypt_text = self.aes.encrypt(text.encode('utf-8'))
        return self.encrypt_text

    def aesdecrypt(self, text):
        if self.model == AES.MODE_CBC:
            self.aes = AES.new(self.key, self.model, self.iv)
        elif self.model == AES.MODE_ECB:
            self.aes = AES.new(self.key, self.model)
        self.decrypt_text = self.aes.decrypt(text)
        self.decrypt_text = self.decrypt_text.strip(b"\x00")
        return self.decrypt_text

import base64
import binascii
def show_data(data):
    #data = "hello".encode()
    data = base64.b64encode(data)
    print("base64编码:",data)
    data = base64.b64decode(data)
    print("base64解码:",data)
    data = binascii.b2a_hex(data)
    print("hexstr编码:",data)
    data = binascii.a2b_hex(data)
    print("hexstr解码:",data)

if __name__ == '__main__':
    # passwd = "123456781234567"
    passwd = "Evomics_passwd_12345"
    iv = '1234567812345678'

    # aescryptor = Aescrypt(passwd, AES.MODE_CBC, iv)  # CBC模式
    aescryptor = Aescrypt(passwd,AES.MODE_ECB,"") # ECB模式
    #text = "好好学习1231"
    text = "A123_B456_C789"
    en_text = aescryptor.aesencrypt(text)
    # en_text=en_text.decode('utf-8')
    print("密文:", en_text)
    show_data(en_text)

    text = aescryptor.aesdecrypt(en_text)
    text= text.decode('utf-8')
    print("明文:", text)
