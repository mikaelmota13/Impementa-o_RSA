from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import os
import time

def gerar_chaves(nome_arquivo_privado, nome_arquivo_publico):
    """
    Gera um par de chaves RSA e as salva em arquivos especificados.
    
    :param nome_arquivo_privado: Nome do arquivo para a chave privada.
    :param nome_arquivo_publico: Nome do arquivo para a chave pública.
    """
    start_time = time.time()
    chave = RSA.generate(2048)
    with open(nome_arquivo_privado, 'wb') as f:
        f.write(chave.export_key())
    with open(nome_arquivo_publico, 'wb') as f:
        f.write(chave.publickey().export_key())
    end_time = time.time()
    print(f"Chaves de bob geradas: {end_time - start_time:.4f} ms")

def carregar_chave_publica(nome_arquivo):
    """
    Carrega uma chave pública de um arquivo.
    
    :param nome_arquivo: Nome do arquivo que contém a chave pública.
    :return: Objeto de chave pública RSA.
    :raises FileNotFoundError: Se o arquivo não for encontrado.
    """
    if not os.path.exists(nome_arquivo):
        raise FileNotFoundError(f"'{nome_arquivo}' não foi encontrado.")
    with open(nome_arquivo, 'rb') as f:
        return RSA.import_key(f.read())

def assinar_mensagem(mensagem, chave_privada):
    """
    Assina uma mensagem utilizando a chave privada RSA.
    
    :param mensagem: Mensagem a ser assinada.
    :param chave_privada: Chave privada RSA utilizada para a assinatura.
    :return: Assinatura da mensagem.
    """
    start_time = time.time()
    hash_obj = SHA256.new(mensagem)
    assinatura = pkcs1_15.new(chave_privada).sign(hash_obj)
    end_time = time.time()
    print(f"Bob: Mensagem para Alice: {mensagem.decode()}")
    #print(f"Hash da Mensagem: {hash_obj.hexdigest()}")
    #print(f"Assinatura (hex): {assinatura.hex()}")
    print(f"Bob: Tempo para assinatura da mensagem: {end_time - start_time:.4f} ms")
    return assinatura

def decifrar_mensagem(mensagem_cifrada, chave_privada):
    """
    Decifra uma mensagem cifrada utilizando a chave privada RSA.
    
    :param mensagem_cifrada: Mensagem cifrada.
    :param chave_privada: Chave privada RSA utilizada para decifrar a mensagem.
    :return: Mensagem decifrada.
    """
    start_time = time.time()
    cipher_rsa = PKCS1_OAEP.new(chave_privada)
    mensagem_decifrada = cipher_rsa.decrypt(mensagem_cifrada)
    end_time = time.time()
    print(f"Bob: Tempo para decifrar a mensagem: {end_time - start_time:.4f} ms")
    return mensagem_decifrada

def main():
    chave_privada_bob = 'bob_private_key.pem'
    chave_publica_bob = 'bob_public_key.pem'
    chave_publica_alice = 'alice_public_key.pem'

    if not os.path.exists(chave_privada_bob) or not os.path.exists(chave_publica_bob):
        gerar_chaves(chave_privada_bob, chave_publica_bob)

    try:
        chave_publica_alice = carregar_chave_publica(chave_publica_alice)
    except FileNotFoundError as e:
        print(e)
        return

    mensagem = b'Esta e uma mensagem autentica de Bob para Alice'
    chave_privada = RSA.import_key(open(chave_privada_bob, 'rb').read())
    assinatura = assinar_mensagem(mensagem, chave_privada)

    with open('mensagem_para_alice.txt', 'wb') as f:
        f.write(mensagem)

    with open('assinatura_bob.txt', 'wb') as f:
        f.write(assinatura)

    print("Bob: Texto claro e hash enviadas para Alice.")

    if os.path.exists('mensagem_cifrada_de_alice.txt'):
        with open('mensagem_cifrada_de_alice.txt', 'rb') as f:
            mensagem_cifrada = f.read()
        
        mensagem_decifrada = decifrar_mensagem(mensagem_cifrada, chave_privada)
        print(f"Bob: Mensagem decifrada de Alice: {mensagem_decifrada.decode()}")
    
#main()

def gerar_chaves_bob():
    chave_privada_bob = 'bob_private_key.pem'
    chave_publica_bob = 'bob_public_key.pem'

    if not os.path.exists(chave_privada_bob) or not os.path.exists(chave_publica_bob):
        gerar_chaves(chave_privada_bob, chave_publica_bob)

def enviar_mensagem_alice():
    chave_privada_bob = 'bob_private_key.pem'
    chave_publica_alice = 'alice_public_key.pem'
    try:
        chave_publica_alice = carregar_chave_publica(chave_publica_alice)
    except FileNotFoundError as e:
        print(e)
        return

    mensagem = b'Da mais uns pontos ai na humilda, esse trabalho ta o maior bucho'
    chave_privada = RSA.import_key(open(chave_privada_bob, 'rb').read())
    assinatura = assinar_mensagem(mensagem, chave_privada)

    with open('mensagem_para_alice.txt', 'wb') as f:
        f.write(mensagem)

    with open('assinatura_bob.txt', 'wb') as f:
        f.write(assinatura)

    print("Bob: Texto claro e hash enviadas para Alice.")

def decifra_msg_alice():
    chave_privada_bob = 'bob_private_key.pem'
    chave_privada = RSA.import_key(open(chave_privada_bob, 'rb').read())
    if os.path.exists('mensagem_cifrada_de_alice.txt'):
        with open('mensagem_cifrada_de_alice.txt', 'rb') as f:
            mensagem_cifrada = f.read()
        
        mensagem_decifrada = decifrar_mensagem(mensagem_cifrada, chave_privada)
        print(f"Bob: Mensagem decifrada de Alice: {mensagem_decifrada.decode()}")