from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import os
import time

def gerar_chaves(arquivo_privado, arquivo_publico):
    """Gera um par de chaves RSA e as salva nos arquivos."""
    inicio = time.time()
    chave = RSA.generate(2048)
    salvar_arquivo(arquivo_privado, chave.export_key())
    salvar_arquivo(arquivo_publico, chave.publickey().export_key())
    print(f"Chaves de Alice geradas em {tempo_execucao(inicio)} ms")

def salvar_arquivo(caminho, conteudo):
    """Salva o conteúdo no caminho especificado."""
    with open(caminho, 'wb') as arquivo:
        arquivo.write(conteudo)

def carregar_chave_publica(caminho_arquivo):
    """Carrega uma chave pública RSA de um arquivo."""
    if not os.path.exists(caminho_arquivo):
        raise FileNotFoundError(f"Arquivo '{caminho_arquivo}' não encontrado.")
    return RSA.import_key(ler_arquivo(caminho_arquivo))

def ler_arquivo(caminho):
    """Lê e retorna o conteúdo de um arquivo."""
    with open(caminho, 'rb') as arquivo:
        return arquivo.read()

def verificar_assinatura(mensagem, assinatura, chave_publica):
    """Verifica a autenticidade de uma assinatura RSA."""
    inicio = time.time()
    hash_mensagem = SHA256.new(mensagem)
    try:
        pkcs1_15.new(chave_publica).verify(hash_mensagem, assinatura)
        print("Assinatura autêntica")
    except (ValueError, TypeError):
        print("Assinatura inválida")
    print(f"Tempo para verificar assinatura: {tempo_execucao(inicio)} ms")

def cifrar_mensagem(mensagem, chave_publica):
    """Cifra uma mensagem utilizando RSA e retorna o texto cifrado."""
    inicio = time.time()
    cipher_rsa = PKCS1_OAEP.new(chave_publica)
    mensagem_cifrada = cipher_rsa.encrypt(mensagem)
    print(f"Tempo para cifrar mensagem: {tempo_execucao(inicio)} ms")
    return mensagem_cifrada

def tempo_execucao(inicio):
    """Calcula e retorna o tempo de execução em milissegundos."""
    return round((time.time() - inicio) * 1000, 4)

def gera_chaves_alice():
    """Gera as chaves de Alice caso não existam."""
    if not os.path.exists('alice_private_key.pem') or not os.path.exists('alice_public_key.pem'):
        gerar_chaves('alice_private_key.pem', 'alice_public_key.pem')

def verifica_autenticidade():
    """Verifica a autenticidade da mensagem e assinatura de Bob."""
    try:
        chave_publica_bob = carregar_chave_publica('bob_public_key.pem')
    except FileNotFoundError as erro:
        print(erro)
        return
    
    mensagem = ler_arquivo('mensagem_para_alice.txt')
    assinatura = ler_arquivo('assinatura_bob.txt')

    verificar_assinatura(mensagem, assinatura, chave_publica_bob)

def enviar_mensagem_cifrada_bob():
    """Cifra e envia uma mensagem para Bob."""
    try:
        chave_publica_bob = carregar_chave_publica('bob_public_key.pem')
    except FileNotFoundError as erro:
        print(erro)
        return

    mensagem = b'Mensagem cifrada para bob'
    mensagem_cifrada = cifrar_mensagem(mensagem, chave_publica_bob)
    salvar_arquivo('mensagem_cifrada_de_alice.txt', mensagem_cifrada)
    print("Mensagem cifrada enviada para Bob.")
