from Crypto.PublicKey import RSA
from oracles import RSA_CRT


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


class RSA_oracle(RSA_CRT):
    def __init__(self, key):
        self._q_inv = modinv(key.q, key.p)
        self._p_inv = modinv(key.p, key.q)
        super(RSA_oracle, self).__init__(key)

    def dec(self, c):
        """
        Decrypt c using self._dec_mod_p and self._dec_mod_q
        :param c: ciphertext
        :return: c ^ d mod n
        """
        m_p = self._dec_mod_p(c)
        m_q = self._dec_mod_q(c)
        # Edited: M is just the CRT output of m_p, m_q
        return self.CRT(m_p, m_q)

    def faulty_dec(self, c):
        """
        Decrypt c using self._faulty_dec_mod_p and self._dec_mod_q
        :param c: ciphertext
        :return: faulty c ^ d mod n
        """
        m_p = self._faulty_dec_mod_p(c)
        m_q = self._dec_mod_q(c)
        # Edited: M is just the CRT output of m_p, m_q
        return self.CRT(m_p, m_q)


    def CRT(self, m_p, m_q):
        """
        Combine m_p and m_q to find m, exactly as was shown in class
        :param m_p: m mod p
        :param m_q: m mod q
        :return: m
        """
        return (m_p * self._q * self._q_inv + m_q * self._p * self._p_inv) % self.n


def bellcore_attack(rsa):
    """
    Given an RSA decryption oracle that utilizes CRT, factor n
    :param rsa: RSA decryption oracle that may calculate c ^ d mod p incorrectly.
    :return: p, q, where p * q = n
    """
    # Edited: Decrypt a message once regularly and once with a fault.
    # We then know that q=gcd(n, M-M') and p=N/q (we would have gotten swapped p,q if the fault was in m_q)
    MESSAGE_TO_DECRYPT = 0x1000
    m = rsa.dec(MESSAGE_TO_DECRYPT)
    m_prime = rsa.faulty_dec(MESSAGE_TO_DECRYPT)
    q = abs(egcd(rsa.n, m - m_prime)[0])
    p = rsa.n // q

    # Test the output
    if p * q == rsa.n:
        return p, q
    else:
        return None


def main():
    n_length = 1024
    key = RSA.generate(n_length)

    rsa = RSA_oracle(key)
    # print(rsa._p, rsa._q)
    print(bellcore_attack(rsa))
    # print(bellcore_attack(rsa) == (rsa._p, rsa._q))


if __name__ == "__main__":
    main()
