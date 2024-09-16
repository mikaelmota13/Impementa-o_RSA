from alice import gera_chaves_alice, verifica_autenticidade, enviar_mensagem_cifrada_bob
from bob import gera_chaves_bob, enviar_mensagem_alice, decifrar_mensagem_alice

def main():
    gera_chaves_bob()
    gera_chaves_alice()

    enviar_mensagem_alice()  # Bob envia mensagem para Alice
    verifica_autenticidade()  # Alice verifica a autenticidade

    enviar_mensagem_cifrada_bob()  # Alice envia mensagem cifrada para Bob
    decifrar_mensagem_alice()  # Bob decifra a mensagem

if __name__ == "__main__":
    main()
