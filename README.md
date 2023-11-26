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

# Tests
Testing function may be seen in the program. It prints three rows in which the first one is where message and its signature are authentic and the following two are those where message or signature where modified.
Function has passed all of these tests and succesfully could tell which pairs of message and signature where modified
