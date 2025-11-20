import os
import random
import re
import string


def py2_oct(n):
    """Return octal string in Python 2 style: '012' instead of '0o12'"""
    return '0' + oct(n)[2:]


def randomize_vars(code, smallVars, lang=""):
    """
    Parses 'code' as a string, and replaces all arbitrary
    numbers with random ones, and randomly names variables. 
    Accounts for quirks in certain languages that enforce
    nonstandard variable naming rules, and ensures no two 
    variables have the same name in a given payload.
    @capnspacehook
    """
    randGen = random.SystemRandom()

    nums = re.findall(r"NUM\d", code)
    vars = re.findall(r"VAR\d+", code)

    if smallVars:
        maxNum = 999
    else:
        maxNum = 9999999

    # Replace NUM placeholders with unique random numbers
    randNums = []
    for num in nums:
        randNum = randGen.randint(0, maxNum)
        while randNum in randNums:
            randNum = randGen.randint(0, maxNum)
        code = code.replace(num, str(randNum))
        randNums.append(randNum)

    # Replace VAR placeholders with unique random variable names
    randVars = []
    for var in vars:
        randVar = gen_random_var(smallVars, lang)
        while randVar in randVars:
            randVar = gen_random_var(smallVars, lang)
        code = code.replace(var, randVar)
        randVars.append(randVar)

    return code


def gen_random_var(smallVars, lang):
    """
    Returns a randomly named variable.
    @capnspacehook
    """
    randGen = random.SystemRandom()

    if smallVars:
        minVarLen = 3
        maxVarLen = 6
    else:
        minVarLen = 6
        maxVarLen = 15

    randVarLen = randGen.randint(minVarLen, maxVarLen)
    randomVar = "".join(randGen.choice(string.ascii_letters) for _ in range(randVarLen))

    # Ruby requires that variables start with a lowercase letter
    if lang == "ruby":
        randomVar = randomVar[0].lower() + randomVar[1:]

    return randomVar


def ipfuscate(ip, smallIP):
    """
    Obfuscate an IP address by converting it to decimal, hex, 
    octal, or a combination of the three.
    Code borrowed from @vysecurity (https://github.com/vysec/IPFuscator)
    Implemented by @capnspacehook
    """
    randGen = random.SystemRandom()

    parts = ip.split('.')

    if not smallIP:
        ip = random_base_ip_gen(parts, smallIP)
    else:
        type_choice = randGen.randint(0, 3)
        decimal = int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])

        if type_choice == 0:
            ip = decimal
        elif type_choice == 1:
            ip = hex(decimal)
        elif type_choice == 2:
            ip = py2_oct(decimal)
        else:
            ip = random_base_ip_gen(parts, smallIP)

    return str(ip)


def random_base_ip_gen(parts, smallIP):
    """
    Used by ipfuscate(), returns an obfuscated IP with random bases.
    Code borrowed from @vysecurity (https://github.com/vysec/IPFuscator)
    Implemented by @capnspacehook
    """
    randGen = random.SystemRandom()

    hexParts = []
    octParts = []

    for i in parts:
        hexParts.append(hex(int(i)))
        octParts.append(py2_oct(int(i)))

    while True:
        randBaseIP = ""
        baseChoices = []
        for i in range(4):
            val = randGen.randint(0, 2)
            baseChoices.append(val)
            if val == 0:
                randBaseIP += parts[i] + '.'
            elif val == 1:
                if not smallIP:
                    pad = '0' * (ord(os.urandom(1)) % 31)
                    hex_part = hexParts[i].replace('0x', '0x' + pad)
                    randBaseIP += hex_part + '.'
                else:
                    randBaseIP += hexParts[i] + '.'
            else:  # octal
                if not smallIP:
                    pad = '0' * (ord(os.urandom(1)) % 31)
                    randBaseIP += pad + octParts[i] + '.'
                else:
                    randBaseIP += octParts[i] + '.'

        # Ensure at least one part is non-decimal
        if any(choice != 0 for choice in baseChoices):
            return randBaseIP[:-1]  # remove trailing '.'


def obfuscate_port(port, smallExpr, lang):
    """
    Obfuscate a port number by replacing the single int
    with an arithmetic expression. Returns a string that
    when evaluated mathematically, is equal to the port entered.
    @capnspacehook 
    """
    randGen = random.SystemRandom()

    exprStr, baseExprPieces = gen_simple_expr(port, smallExpr)

    if smallExpr:
        portExpr = exprStr % (baseExprPieces[0], baseExprPieces[1], baseExprPieces[2])
    else:
        subExprs = []
        for piece in baseExprPieces:
            expr, pieces = gen_simple_expr(piece, smallExpr)
            subExprs.append(expr % (pieces[0], pieces[1], pieces[2]))
        portExpr = exprStr % (subExprs[0], subExprs[1], subExprs[2])

    # Randomly replace '+N' with '-(-N)'
    match = re.search(r"\+\d+", portExpr)
    while match:
        start, end = match.span()
        if randGen.randint(0, 1):
            portExpr = portExpr[:start] + "-(-" + portExpr[start+1:end] + ")" + portExpr[end:]
        match = re.search(r"\+\d+", portExpr[end:])

    # Fix '--N' → '-(N)'
    match = re.search(r"--\d+", portExpr)
    while match:
        start, end = match.span()
        portExpr = portExpr[:start] + "-(" + portExpr[start+1:end] + ")" + portExpr[end:]
        match = re.search(r"--\d+", portExpr[end:])

    # Bash requires $((...))
    if lang == "bash":
        portExpr = "$((" + portExpr + "))"

    return portExpr


def gen_simple_expr(n, smallExpr):
    """
    Generates a simple mathematical expression of 3 terms
    that equal the number passed. Returns a template
    expression string, and a tuple of the values of the 
    terms in the generated expression.
    @capnspacehook
    """
    randGen = random.SystemRandom()

    if isinstance(n, str):
        n = int(eval(n))

    if n == 0:
        N = 0
        while N == 0:
            N = randGen.randint(-99999, 99999)
    else:
        N = n

    choice = randGen.randint(0, 2)
    if choice == 0:  # addition
        if N < 0:
            left = randGen.randint(N * 2, -N + 1)
            right = randGen.randint(N - 1, -N * 2)
        else:
            left = randGen.randint(-N * 2, N - 1)
            right = randGen.randint(-N + 1, N * 2)
        total = left + right
        offset = n - total if total < n else total - n
        expr = "((%s+%s)+%s)" if total < n else "(-(-(%s+%s)+%s))"

    elif choice == 1:  # subtraction
        if N < 0:
            left = randGen.randint(N - 1, -N * 2)
            right = randGen.randint(N * 2, N - 1)
        else:
            left = randGen.randint(-N + 1, N * 2)
            right = randGen.randint(-N * 2, N + 1)
        total = left - right
        offset = n - total if total < n else total - n
        expr = "((%s-%s)+%s)" if total < n else "(-(-(%s-%s)+%s))"

    else:  # multiplication
        if N < 0:
            left = randGen.randint(int(N / 2), -int(N / 2) - 2)
            right = randGen.randint(int(N / 3), -int(N / 3))
        else:
            left = randGen.randint(-int(n / 2), int(n / 2) + 2)
            right = randGen.randint(-int(n / 3), int(n / 3))
        total = left * right
        offset = n - total if total < n else total - n
        expr = "((%s*%s)+%s)" if total < n else "(-(-(%s*%s)+%s))"

    # Recursively obfuscate zero terms if not in small mode
    if not smallExpr:
        if left == 0:
            zeroExpr, terms = gen_simple_expr(0, smallExpr)
            left = zeroExpr % terms
        if right == 0:
            zeroExpr, terms = gen_simple_expr(0, smallExpr)
            right = zeroExpr % terms
        if offset == 0:
            zeroExpr, terms = gen_simple_expr(0, smallExpr)
            offset = zeroExpr % terms

    return (expr, (left, right, offset))