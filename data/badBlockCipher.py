#!python3
# "bad block cipher"

import random

sboxSize = 5
blockSize = 5
keySize = 7

def myhex(state):
	return "0x%0.10X" % state

def addKey(state, key):
	expansion = 0
	for i in range(blockSize):
		expansion  = expansion<<8
		key0 = key
		if (i%2==1):
			key0 = key ^ 0xFF
		expansion = expansion | key0
	return state ^ expansion

def sbox(state):
	box = [22, 0, 19, 9, 15, 3, 21, 18, 4, 26, 28, 13, 27, 5, 25, 31, 29, 12, 24, 6, 23, 8, 2, 11, 16, 30, 14, 10, 20, 7, 17, 1]
	result = 0
	loops = blockSize*8//sboxSize
	for i in range(loops):
		result=result<<sboxSize
		result = result | box[(state>>sboxSize*(loops-i-1))&0x1F]
	
	return result

def encrypt_block(message, key):
	if len("%0.10X"%message)//2!= blockSize or len("%0.14X" %key)//2!=keySize :
		return None # bad length
	state = message
	for i in range(1,7):
		# xor key byte
		state = addKey(state, (key>>(8*(keySize-i)))&0xFF )
		state = sbox(state)
		tmp = (state& 0xFF) << 8*(blockSize-1)
		state = (state>>8) | tmp
	state = addKey(state, key&0xFF ) 
	return state
	
def example():
	msg = 0x00DEADBEEF
	key = 0xC0FFEE15C0FFEE
	print("msg:\t", myhex(msg))
	print("key:\t", myhex(key))
	cipher = encrypt_block(msg, key)
	print("res:\t", myhex(cipher) )

example()