import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import RSA

from app import keys


def generate_rsa_key():
    return RSA.generate(1024)


def encrypt(ms, public_key):
    # создаём объект для шифрования с применением паддинга PKCS1
    cipher = PKCS1_v1_5.new(public_key)

    # переводим сообщение в байты
    # шифруем, а результат кодируем в base64
    # переводим из байтов в строку
    return base64.b64encode(
        cipher.encrypt(
            ms.encode('utf-8')
        )
    ).decode('utf-8')


def decrypt(ms, private_key):
    # создаём объект для дешифрации
    cipher = PKCS1_v1_5.new(private_key)
    
    # предположим, что средняя длина сообщения - 45
    dsize = SHA.digest_size
    sentinel = Random.new().read(45 + dsize)

    # раскодируем из base64
    # зашифруем и переведём из байтов в строку
    return cipher.decrypt(
        base64.b64decode(ms), 
        sentinel
    ).decode('utf-8')


# переводим публичный ключ в формат pkcs1
def key2pubpkcs(key):
    return key.publickey().exportKey().decode('utf-8')


# переводим приватный ключ в формат pkcs1
def key2pripkcs(key):
    return key.exportKey().decode('utf-8')


# переводим из pkcs1 в объект типа RSA
def pkcs2key(pkcs):
    return RSA.import_key(pkcs.encode('utf-8'))


# ищем пользователя
def search_for_user(data, username):
    return data.get(username)


# проверяем пароль
def check_password(user, password):
    return password == decrypt(user['password'], keys)
