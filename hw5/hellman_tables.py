"""
An algorithm for a time-memory tradeoff
"""

from prf import PRF
from os import urandom
from collections import defaultdict


class ModifiedPRF(object):
    def __init__(self, f):
        """
        Modifies an expanding or compressing PRF to work with hellman's algorithm
        :param f: oracle for a random function
        """
        self.f = f

    def calc(self, x):
        """
        Calculate a modified f
        You are allowed to assume that domain <= (range)^2 and range <= (domain)^2
        :param x: input
        :return: random consistent output
        """
        domain = self.f.domain
        rang = self.f.rang

        if domain < rang:
            return self.f.calc(x % domain)
        elif domain > rang:
            return self.f.calc(x + ((x + 1)%domain)*rang)
        else:
            return self.f.calc(x)

    def recover_x(self, x):
        """
        Given a value x returned by Hellman's algorithm over self.calc and y, return x' such that self.f.calc(x') = y
        :param x: x such that self.calc_new(x) = y
        :return: x' such that self.f.calc(x') = y
        """
        domain = self.f.domain
        rang = self.f.rang

        if domain < rang:
            return (x%domain)
        elif domain > rang:
            return x + ((x + 1)%domain)*rang
        else:
            return x


def hellman_preprocess(m, t, f_tag):
    """
    Preprocess hellman tables
    :param m: number of chains in each table
    :param t: length of the chains, and the number of tables
    :param f_tag: oracle for a random function
    :return: a list of tables, where each table is a dictionary from the end points to the start points
    """
    tables = []
    for i in range(t):
        table = defaultdict(list)

        for _ in range(m):
            start = int.from_bytes(urandom(f_tag.f.domain_bytes), byteorder='big')
            curr = start
            for _ in range(t):
                next = f_tag.calc((curr + i) % f_tag.f.domain)
                curr = next
            table[curr].append(start)

        tables.append(table)
        if i % 32 == 0:
            print(i)
    return tables


def hellman_online(tables, t, y, f_tag):
    """
    Find x such that f(x)=y
    :param tables: preprocessed tables
    :param t: length of the chains, and the number of tables
    :param y: input
    :param f_tag: modified oracle for a random function
    :return: x such that f(x)=y if the attack succeeded, else None
    """
    for i in range(len(tables)):
        curr = y
        for _ in range(t):
            if len(tables[i][curr]) > 0:
                for a in tables[i][curr]:
                    for _ in range(t):
                        if f_tag.calc((a + i) % f_tag.f.domain) == y:
                            return (a+i)%f_tag.f.domain
                        a = f_tag.calc((a + i) % f_tag.f.domain)
            curr = f_tag.calc((curr + i) % f_tag.f.domain)
    return None


def run_hellman(f, m, t):
    """
    Run the Hellman algorithm to reverse f
    :param f: oracle for a random function
    :param m: number of chains in each table
    :param t: length of the chains, and the number of tables
    :return: the success rate of the algorithm over 100 inputs
    """
    f_tag = ModifiedPRF(f)

    tables = hellman_preprocess(m, t, f_tag)
    print("Loaded tables")

    success_count = 0
    for _ in range(100):
        y = f.calc(int.from_bytes(urandom(f.domain_bytes), byteorder='big'))
        x = hellman_online(tables, t, y, f_tag)
        if x is not None:
            x = f_tag.recover_x(x)
            if f.calc(x) == y:
                success_count += 1
    return success_count


def test_1():
    # The case where domain = range
    key = b'j\xb1\xd5\xfa\x92\x11X\x12\x00\xde3\xae\x16L8['
    block_size = 3
    m = 2 ** 8
    t = 2 ** 8

    f = PRF(key, block_size)
    return run_hellman(f, m, t)


def test_2():
    # The case where domain < range
    key = b'8{8H\x00\xe5\xa6\xc7BTs=\xba\xd5\x18\xe6'
    domain_size = 2
    rang_size = 3
    # started by using the formula T=t^2~N^(2/3) from the tradeoff formula,
    # but switched to these numbers for a better performance rate
    m = 2 ** 12
    t = 2 ** 4

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def test_3():
    # The case where domain > range
    key = b'\xa42A\xcf\x0c\xf4\x001\xff\xd7\xaa\x8f\tZ\x11\xdd'
    domain_size = 3
    rang_size = 2
    # started by using the formula T=t^2~N^(2/3) from the tradeoff formula,
    # but switched to these numbers for a better performance rate
    m = 2 ** 16
    t = 2 ** 4

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def main():
    print("Test 1 success rate:", test_1())
    print("Test 2 success rate:", test_2())
    print("Test 3 success rate:", test_3())


if __name__ == "__main__":
    main()
