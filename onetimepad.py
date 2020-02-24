import binascii
c0 = '588B12E8140D66511035513D07656FF4A29135FA7814A41C367BFCBC88'
c1 = "588B16E9190D2A1615265C3C033179B1A88A67F93D10EB172D62E9A69E"
c2 = "5FCE13E40A41345317275068097F6FF4BF9678F93D13E515797EEDAD88"
c3 = "42CE06F40A08324F42354229147464B1B88C35F56E43E7032C76E1B597"
c4 = "44D800A10C1629160435563C09632AB5BE8B7DF97317ED123861E1BB95"
c5 = "45C300A11D0F235B1B745E26096679F4BF9770BC7C0FE31E2B7CFCBC96"

ciphertexts = [c0, c1, c2, c3, c4, c5] #array of all ciphertexts

# finds the xor of 2 hex's and returns ascii
def str_xor(hex1, hex2):
    result = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(hex1, hex2)])
    print(result)
    return bytes.fromhex(result).decode('ISO-8859-1')

possible_space_indexes = {}  # stores how many space chars are found

for ciphertext in ciphertexts:
    possible_space_indexes[ciphertext] = [0] * 29

found_key = [None] * 29  # chars of the key that are found
known_key_indexes = []  # indexes for parts of the key that are known

for ciphertext in ciphertexts:  # for each ciphertext
    for ciphertext2 in ciphertexts:  # go through each other ciphertext
        if (ciphertext != ciphertext2):
            for charindex, char in enumerate(str_xor(ciphertext,ciphertext2)):  # grab each char and charindex from the xor of the selected ciphertexts
                if char.isprintable() and char.isalpha():  # if the char is a printable character and is alphanumeric
                    possible_space_indexes[ciphertext][charindex] += 1  # add one to the counter for number of times a character can possibly be seen as a space

    known_space_indexes = []

    for index, value in enumerate(possible_space_indexes[ciphertext]):  # for each char in the current ciphertext
        print (value)
        if value >= 4:  # if the value of the counter is at least 4
            known_space_indexes.append(index)  # append the index to the list of known indexes

    space_xor = str_xor(ciphertext, "20" * 29)  # xor the current ciphertext with a string of all space chars

    for index in known_space_indexes:  # for each index

        found_key[index] = '{:02X}'.format(ord(space_xor[index]))  # convert xor back to hex

        known_key_indexes.append(index)  # add the index to the known key indexes

found_key_final = ''.join([x if x is not None else '00' for x in found_key])  # create the final key from the vals in found_key, if the val wasn't found put 00

output = str_xor(found_key_final, c0)  # xor the found key with the target ciphertext

print(''.join([x if index in known_key_indexes else '#' for index, x in enumerate(output)]))  # print out the xor result, if the char isn't known put a #

#manually observe key

#result was: # #i#l gra#u#te### few #o####
# i will graduate in few months

p0 = "i will graduate in few months"
p0e = p0.encode('utf-8').hex()

key = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(p0e, c0)])

print(key)

for ciphertext in ciphertexts: #xor each ciphertext with the final key
    print(str_xor(key, ciphertext))

## i will graduate in few months
#69207368616c6c2077726974652073656375726520736f667477617265
#i shall write secure software
#6e65766572207265757365206f6e652074696d6520706164206b657973
#never reuse one time pad keys
#73656375726974792061776172656e657373206973206372756369616c
#security awareness is crucial
#7573652074776f20666163746f722061757468656e7469636174696f6e
#use two factor authentication
#74686520656e656d79206b6e6f77732074686520616c676f726974686d
#the enemy knows the algorithm