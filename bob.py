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
    print(f"Chaves de Bob geradas em {tempo_execucao(inicio)} ms")

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

def assinar_mensagem(mensagem, chave_privada):
    """Assina uma mensagem com a chave privada RSA."""
    inicio = time.time()
    hash_mensagem = SHA256.new(mensagem)
    assinatura = pkcs1_15.new(chave_privada).sign(hash_mensagem)
    print(f"Mensagem assinada em {tempo_execucao(inicio)} ms")
    return assinatura

def decifrar_mensagem(mensagem_cifrada, chave_privada):
    """Decifra uma mensagem utilizando RSA."""
    inicio = time.time()
    cipher_rsa = PKCS1_OAEP.new(chave_privada)
    mensagem_decifrada = cipher_rsa.decrypt(mensagem_cifrada)
    print(f"Mensagem decifrada em {tempo_execucao(inicio)} ms")
    return mensagem_decifrada

def tempo_execucao(inicio):
    """Calcula e retorna o tempo de execução em milissegundos."""
    return round((time.time() - inicio) * 1000, 4)

def gera_chaves_bob():
    """Gera as chaves de Bob caso não existam."""
    if not os.path.exists('bob_private_key.pem') or not os.path.exists('bob_public_key.pem'):
        gerar_chaves('bob_private_key.pem', 'bob_public_key.pem')

def enviar_mensagem_alice():
    """Assina e envia uma mensagem para Alice."""
    try:
        chave_publica_alice = carregar_chave_publica('alice_public_key.pem')
    except FileNotFoundError as erro:
        print(erro)
        return

    mensagem = b'Mensagem de bob para alice'
    chave_privada_bob = RSA.import_key(ler_arquivo('bob_private_key.pem'))
    assinatura = assinar_mensagem(mensagem, chave_privada_bob)
    salvar_arquivo('mensagem_para_alice.txt', mensagem)
    salvar_arquivo('assinatura_bob.txt', assinatura)
    print("Mensagem e assinatura enviadas para Alice.")

def decifrar_mensagem_alice():
    """Decifra a mensagem recebida de Alice."""
    chave_privada_bob = RSA.import_key(ler_arquivo('bob_private_key.pem'))
    mensagem_cifrada = ler_arquivo('mensagem_cifrada_de_alice.txt')
    mensagem_decifrada = decifrar_mensagem(mensagem_cifrada, chave_privada_bob)
    print(f"Mensagem decifrada de Alice: {mensagem_decifrada.decode()}")
