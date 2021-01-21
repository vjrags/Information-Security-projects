#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto import Random

KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size

_random_gen = Random.new()
_key = _random_gen.read(KEY_LENGTH)


def _add_padding(msg):
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return msg + padding


def _remove_padding(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return None
    for i in range(1, pad_len):
        if data[-i-1] != pad_len:
            return None
    return data[:-pad_len]


def encrypt(msg):
    iv = _random_gen.read(AES.block_size)
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(_add_padding(msg))


def _decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return _remove_padding(cipher.decrypt(data[BLOCK_SIZE:]))


def is_padding_ok(data):
    return _decrypt(data) is not None


if __name__ == '__main__':
    cleartext = b'Attack at dawn'
    ciphertext = encrypt(cleartext)

    print("cleartext:", cleartext)
    print("decrypted message:", _decrypt(ciphertext))
    print("padding is ok:", is_padding_ok(ciphertext))


def attack_message(msg):

    cipherfake=[0] * 16
    plaintext = [0] * 16
    current = 0
    message=""


    #I devide the list of bytes in blocks, and I put them in another list
    number_of_blocks = int(len(msg)/BLOCK_SIZE)
    blocks = [[]] * number_of_blocks
    for i in (range(number_of_blocks)):
        blocks[i] = msg[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]

    for z in range(len(blocks)-1):  #for each message, I calculate the number of block
        for itera in range (1,17): #the length of each block is 16. I start by one because than I use its in a counter
            for v in range(256):
                cipherfake[-itera]=v
                if is_padding_ok(bytes(cipherfake)+blocks[z+1]): #the idea is that I put in 'is_padding_ok' the cipherfake(array of all 0) plus the last block
                                                                 #if the function return true I found the value
                    current=itera
                    plaintext[-itera]= v^itera^blocks[z][-itera]

            for w in range(1,current+1):
                cipherfake[-w] = plaintext[-w]^itera+1^blocks[z][-w] #for decode the second byte I must set the previous bytes with 'itera+1'


        for i in range(16):
            if plaintext[i] >= 32:
                char = chr(int(plaintext[i]))
                message += char

    #print("Crack: " + message + "\n")
    return str.encode(message)






def test_the_attack():

    messages = str.argv[1]
    for msg in messages:
        print('Testing:', msg)
        cracked_ct = attack_message(encrypt(msg))
        assert cracked_ct == msg


if __name__ == '__main__':
    test_the_attack()