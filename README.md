# RSA_Signing

This program is a python implementation of RSA signing and verification of digital signature, it also can be used to encrypt and decrypt small messages, however, it's not recommended

# How to use
To sign a message run a following code:

message = "*Your message*"

hashed, signature = sign(message, pb_key)

It returns a tuple consisting of hash value of the message (sha-256) and a digital signature attached to this message.

To verify signature use:

print(verify(hashed, signature, pr_key))

It prints if the message is authentic

# Notes
This code uses updated pow module. If you have Python version which is older than 3.5 please consider rewriting parts of code where pow module is used

# Time
Generation of large prime numbers is a time-consuming task, therefore you may consider not generating it every time. Instead you should try generating a pair of keys and use for a some period of time

Time for generating a pair of keys takes much more time than signing and verification. Also, it should be noted that message length doesn't influence signing and verification speed much as message hash is being encrypted instead of message's content and hash is always 256 bits long.

# Tests
Testing function may be seen in the program. It prints three rows in which the first one is where message and its signature are authentic and the following two are those where message or signature where modified.
Function has passed all of these tests and succesfully could tell which pairs of message and signature where modified
