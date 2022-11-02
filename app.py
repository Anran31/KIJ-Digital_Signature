import sys
import os
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

SIGN_LEN = 256

input_message = [
    '\r----------',
    'Available commands:',
    '/generate_key_pair                         Generate a private and public key pair',
    '/sign <PDF File> <Private Key File>        Sign a PDF file',
    '/verify <PDF File> <Public Key File>       Verify signature in a PDF file',
    '/quit                                      Exit the app',
    '----------',
    '>> '
]

return_code = {0: 'Wrong file type, only PDF file can be signed with \'.pem\' key', 1: "Key Pair generated", 2: "File signed", 3: "Signature is valid",
               - 1: "file(s) not found", -2: "Key couldn't be used to sign file", -3: "Signature is invalid"}


def print_command():
    print('\n'.join(input_message), end='')


def generate_key_pair():
    privateKey = RSA.generate(2048)
    with open('private_key.pem', 'wb') as priv_key:
        priv_key.write(privateKey.export_key('PEM'))

    publicKey = privateKey.publickey()
    with open('public_key.pem', 'wb') as pub_key:
        pub_key.write(publicKey.export_key('PEM'))

    return 1



def checkFiles(pathList):
    for path in pathList:
        if not os.path.isfile(path):
            return -1
        if path[-3:] not in ['pdf', 'pem']:
            return 0
    return 1


def sign(filePath, keyPath):
    if not checkFiles([filePath, keyPath]):
        return -1

    with open(filePath, 'rb') as in_file:
        byteStream = in_file.read()

    key = RSA.import_key(open(keyPath).read())
    h = SHA256.new(byteStream)
    signer = pss.new(key)

    try:
        signature = signer.sign(h)
    except:
        return -2

    fileName = os.path.basename(filePath)
    savedFileName = 'signed_' + fileName

    savedFilePath = '\\'.join(filePath.split('\\')[:-1]) + '\\'
    if savedFilePath != '\\':
        savedFilePath += savedFileName
    else:
        savedFilePath = savedFileName   

    with open(savedFilePath, 'wb') as signed:
        signed.write(byteStream+signature)

    return 2


def verify(filePath, keyPath):
    if not checkFiles([filePath, keyPath]):
        return -1

    with open(filePath, 'rb') as in_file:
        byteStream = in_file.read()
        doc_signature = byteStream[-SIGN_LEN:]
        byteStream = byteStream[:-SIGN_LEN]

    pub_key = RSA.import_key(open(keyPath).read())
    h = SHA256.new(byteStream)
    verifier = pss.new(pub_key)

    try:
        verifier.verify(h, doc_signature)
        return 3
    except:
        return -3


COMMANDS = {
    '/sign': sign,
    '/verify': verify,
}


if __name__ == "__main__":
    print_command()
    while True:
        commands = input()
        available_commands = ('/generate_key_pair',
                              '/sign', '/verify', '/quit')

        command = commands.split(" ", 2)

        if command[0] not in available_commands:
            print(
                f'\rCommand {command[0]} not found.\n----------\n>> ', end='')
        elif command[0] == available_commands[0]:
            result = generate_key_pair()
            print(return_code[result])
        elif command[0] == available_commands[-1]:
            sys.exit()
        else:
            result = COMMANDS[command[0]](command[1], command[2])
            print(return_code[result])
        print_command()
