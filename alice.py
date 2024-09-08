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
    print(f"Chaves de alice geradas: {end_time - start_time:.4f} ms")

def carregar_chave_publica(nome_arquivo):
    """
    Carrega uma chave pública de um arquivo.
    
    :param nome_arquivo: Nome do arquivo que contém a chave pública.
    :return: Objeto de chave pública RSA.
    :raises FileNotFoundError: Se o arquivo não for encontrado.
    """
    if not os.path.exists(nome_arquivo):
        raise FileNotFoundError(f"Alice: '{nome_arquivo}' não foi encontrado.")
    with open(nome_arquivo, 'rb') as f:
        return RSA.import_key(f.read())

def verificar_assinatura(mensagem, assinatura, chave_publica):
    """
    Verifica a assinatura de uma mensagem utilizando a chave pública RSA.
    
    :param mensagem: Mensagem cuja assinatura será verificada.
    :param assinatura: Assinatura a ser verificada.
    :param chave_publica: Chave pública RSA utilizada para a verificação.
    """
    start_time = time.time()
    hash_obj = SHA256.new(mensagem)
    try:
        pkcs1_15.new(chave_publica).verify(hash_obj, assinatura)
        print("Alice: A assinatura é AUTENTICA")
        #print("A assinatura é AUTENTICA.\nMensagem para Bob: ", mensagem.decode())
    except (ValueError, TypeError):
        print("Alice: A assinatura nao e AUTENTICA!")
    end_time = time.time()
    print(f"Alice: Tempo para verificar a assinatura: {end_time - start_time:.4f} ms")
    #print(f"Mensagem: {mensagem.decode()}")
    #print(f"Hash da Mensagem: {hash_obj.hexdigest()}")
    #print(f"Assinatura (hex): {assinatura.hex()}")

def cifrar_mensagem(mensagem, chave_publica):
    """
    Cifra uma mensagem utilizando a chave pública RSA.
    
    :param mensagem: Mensagem a ser cifrada.
    :param chave_publica: Chave pública RSA utilizada para a cifração.
    :return: Mensagem cifrada.
    """
    start_time = time.time()
    cipher_rsa = PKCS1_OAEP.new(chave_publica)
    mensagem_cifrada = cipher_rsa.encrypt(mensagem)
    end_time = time.time()
    print(f"Alice: Tempo para cifrar a mensagem: {end_time - start_time:.4f} ms")
    return mensagem_cifrada

def main():
    chave_privada_alice = 'alice_private_key.pem'
    chave_publica_alice = 'alice_public_key.pem'
    chave_publica_bob = 'bob_public_key.pem'
    mensagem_para_alice = 'mensagem_para_alice.txt'
    assinatura_bob = 'assinatura_bob.txt'

    if not os.path.exists(chave_privada_alice) or not os.path.exists(chave_publica_alice):
        gerar_chaves(chave_privada_alice, chave_publica_alice)
    
    try:
        chave_publica_bob = carregar_chave_publica(chave_publica_bob)
    except FileNotFoundError as e:
        print(e)
        return

    if not os.path.exists(mensagem_para_alice) or not os.path.exists(assinatura_bob):
        print("Alice: O Texto claro ou hash não foi encontrado.")
        return

    with open(mensagem_para_alice, 'rb') as f:
        mensagem = f.read()
    
    with open(assinatura_bob, 'rb') as f:
        assinatura = f.read()

    verificar_assinatura(mensagem, assinatura, chave_publica_bob)

    mensagem_para_bob = b'se n funcionar e viado'
    mensagem_cifrada = cifrar_mensagem(mensagem_para_bob, chave_publica_bob)

    with open('mensagem_cifrada_de_alice.txt', 'wb') as f:
        f.write(mensagem_cifrada)
    
    print("Alice: Mensagem cifrada enviada para Bob.")

#main()

def gera_chaves_alice():
    chave_privada_alice = 'alice_private_key.pem'
    chave_publica_alice = 'alice_public_key.pem'

    if not os.path.exists(chave_privada_alice) or not os.path.exists(chave_publica_alice):
        gerar_chaves(chave_privada_alice, chave_publica_alice)

def verifica_aut():
    chave_publica_bob = 'bob_public_key.pem'
    mensagem_para_alice = 'mensagem_para_alice.txt'
    assinatura_bob = 'assinatura_bob.txt'

    try:
        chave_publica_bob = carregar_chave_publica(chave_publica_bob)
    except FileNotFoundError as e:
        print(e)
        return

    if not os.path.exists(mensagem_para_alice) or not os.path.exists(assinatura_bob):
        print("Alice: O Texto claro ou hash não foi encontrado.")
        return

    with open(mensagem_para_alice, 'rb') as f:
        mensagem = f.read()
    
    with open(assinatura_bob, 'rb') as f:
        assinatura = f.read()

    verificar_assinatura(mensagem, assinatura, chave_publica_bob)

def envia_msg_cifrada_bob():
    chave_publica_bob = 'bob_public_key.pem'

    try:
        chave_publica_bob = carregar_chave_publica(chave_publica_bob)
    except FileNotFoundError as e:
        print(e)
        return

    mensagem_para_bob = b'Esta e uma mensagem cifrada para Bob'
    mensagem_cifrada = cifrar_mensagem(mensagem_para_bob, chave_publica_bob)

    with open('mensagem_cifrada_de_alice.txt', 'wb') as f:
        f.write(mensagem_cifrada)
    
    print("Alice: Mensagem cifrada enviada para Bob.")