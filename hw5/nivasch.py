"""
An algorithm for cycle detection
"""

from prf import PRF


def find_cycle(f, k, start):
    """
    Return a point x, where x is the first point detected by the Nivasch algorithm
    :param f: oracle for a random function
    :param k: the number of stacks to use
    :param start: starting point for the algorithm
    :return: x, where x is a point inside of a cycle
    """
    stacks = []
    for _ in range(k):
        stacks.append([])
    
    stacks[start % k].append(start)
    next = start
    while True:
        next = f.calc(next)
        if next in stacks[next % k]:
            return next

        if (len(stacks[next % k]) == 0):
            stacks[next % k].append(next)
            continue

        while stacks[next % k][-1] > next:
            stacks[next % k].pop()
            if len(stacks[next % k]) == 0:
                break
        stacks[next % k].append(next)



def main():
    key = b'\xf7\xf2&\x1cam\x8fN|9\xa1\x00N\xd3@"'
    block_size = 4
    f = PRF(key, block_size)
    start = 0
    k = 100

    x = find_cycle(f, k, start)

    # test vector
    if x == 8391269:
        print("Success")
    else:
        print("Fail")


if __name__ == "__main__":
    main()
