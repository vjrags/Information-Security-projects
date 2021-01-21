import hashlib
import roots
import sys

#Take in input arguments


in_string = sys.argv[1]

#Grab SHA-1 hash from argument

m = hashlib.sha1()
m.update(in_string)
sha_hash= m.hexdigest()

#format message with appropriate f bytes

x_string = "0001ffffffffff003021300906052b0e03021a05000414" + sha_hash + (213 * 2) * "0"
#convert to integer
temp_x = int(x_string, 16)

#take cubic root of message

new_x_tuple = roots.integer_nthroot(temp_x, 3)

#grab almost complete signature
new_x = new_x_tuple[0]
#Not sure why this is necessary, but after testing, this should give correct answers
forged_signature = new_x + 1

#convert to b64

b64_x = roots.integer_to_base64(forged_signature)

print b64_x