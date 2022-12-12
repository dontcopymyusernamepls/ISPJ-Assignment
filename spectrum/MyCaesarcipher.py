LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'    


def encrypt(key, plaintext_utf8):
    ciphertext_utf8 = ""

    for character in plaintext_utf8:
        if character in LETTERS:
            # get the character position
            position = LETTERS.find(character) 
            position = position + key

            # wrap-around if position >= length of LETTERS
            if position >= len(LETTERS):
                position = position - len(LETTERS)

            # append encrypted character
            ciphertext_utf8 = ciphertext_utf8 + LETTERS[position]

        else:
            # append character without encrypting
            ciphertext_utf8 = ciphertext_utf8 + character

    return ciphertext_utf8


def decrypt(key, ciphertext_utf8):
    decryptedtext_utf = ""

    for character in ciphertext_utf8:
        if character in LETTERS:
            # get the character position
            position = LETTERS.find(character) # hint: use find()
            position = position - key

            # wrap-around if position >= length of LETTERS
            if position < 0:
                position = position - len(LETTERS)

            # append encrypted character
            decryptedtext_utf = decryptedtext_utf + LETTERS[position]

        else:
            # append character without encrypting
            decryptedtext_utf = decryptedtext_utf + character

    return decryptedtext_utf
