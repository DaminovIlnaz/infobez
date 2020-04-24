import os
import hashlib
from Crypto.Cipher import AES


def malicious_g_attack():
    """
    Имитирует разрыв Диффи-Хеллмана с согласованными группами с использованием вредоносных параметров «g».
    """

    p = DiffieHellman.DEFAULT_P
    return_vals = []

    # Это перебирает значения, предложенные для «g» вопросом.
    for g in [1, p, p - 1]:

        # Шаг 1: MITM изменяет значение по умолчанию, отправленное Алисой Бобу с принудительным значением.
        alice = DiffieHellman()
        bob = DiffieHellman(g=g)

        # Шаг 2: Боб получает это принудительное g и посылает ACK Алисе.

        # Шаг 3: Алиса вычисляет A и отправляет его в MITM (думая о Бобе).
        A = alice.gen_public_key()

        # Шаг 4: Боб вычисляет B и отправляет его в MITM (думает об Алисе).
        B = bob.gen_public_key()

        # Шаг 5: Алиса отправляет свое зашифрованное сообщение Бобу (без знания MITM).
        _msg = b"Hello, how are you?"
        _a_key = hashlib.sha1(str(alice.gen_shared_secret_key(B)).encode()).digest()[:16]
        _a_iv = os.urandom(AES.block_size)
        a_question = AES_CBC_encrypt(_msg, _a_iv, _a_key) + _a_iv

        # Шаг 6: Боб получает сообщение, отправленное Алисой (не зная об атаке)
        # Однако на этот раз Боб не сможет расшифровать его, потому что (если я понял
        # Задача правильно задана) Алиса и Боб теперь используют разные значения g.

        # Шаг 7: MITM расшифровывает вопрос Алисы.
        mitm_a_iv = a_question[-AES.block_size:]

        # Когда g равен 1, секретный ключ также равен 1.
        if g == 1:
            mitm_hacked_key = hashlib.sha1(b'1').digest()[:16]
            mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)

        # Когда g равно p, оно работает так же, как и при атаке S5C34 (секретный ключ равен 0).
        elif g == p:
            mitm_hacked_key = hashlib.sha1(b'0').digest()[:16]
            mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)

        # Когда g равно p - 1, секретный ключ равен (-1) ^ (ab), что равно (+1% p) или (-1% p).
        # Мы можем попробовать оба варианта, а затем проверить заполнение, чтобы увидеть, какой из них правильный.
        else:

            for candidate in [str(1).encode(), str(p - 1).encode()]:
                mitm_hacked_key = hashlib.sha1(candidate).digest()[:16]
                mitm_hacked_message = AES_CBC_decrypt(a_question[:-AES.block_size], mitm_a_iv, mitm_hacked_key)
                if PKCS7_padded(mitm_hacked_message):
                    mitm_hacked_message = PKCS7_unpad(mitm_hacked_message)
                    break
        print(mitm_hacked_message)

malicious_g_attack()