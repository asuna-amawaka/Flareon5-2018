#Challenge 6 Soln by Asuna
#Requires manually pressing "Enter" 666 times (just hold it down) because I'm lazy to change it after it worked.. :D

import gdb
import base64
import sys
import binascii
import struct

def text_to_bytes(s):

	byteList = []

	for byte in s:
	    byteList.append(ord(byte))

	return byteList

def hex_to_bytes(hexStr):

	byteList = []
	for i in range(0, len(hexStr), 2):
	    byte = hexStr[i:i+2]
	    byteList.append(int('0X' + byte, 16))

	return byteList

def bytes_to_text(ByteList):

	s = ''
	for byte in ByteList:
	    s += chr(byte)
	
	return s

def crypt(PlainBytes, KeyBytes):
	keystreamList = []
	cipherList = []

	keyLen = len(KeyBytes)
	plainLen = len(PlainBytes)
	S = list(range(256))
	j = 0
	for i in range(256):
		j = (j + S[i] + KeyBytes[i % keyLen]) % 256
		temp=S[i]
		S[i]=S[j]
		S[j]=temp

	i = 0
	j = 0
	for m in range(plainLen):
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		k = S[(S[i] + S[j]) % 256]
		keystreamList.append(k)
		cipherList.append(k ^ PlainBytes[m])
	
	return cipherList

def decrypt(text):
	KeyBytes = text_to_bytes('Tis but a scratch.')
	PlainBytes = crypt(hex_to_bytes(text), KeyBytes)
	return bytes_to_text(PlainBytes)


def base64_decode(encoded_data, b64_alpha):
	decoded = ""
	unpadded = encoded_data
	left = 0
	for i in range(0, len(unpadded)):
		if (left == 0):
			left = 6
		else:
			v1 = b64_alpha.index(unpadded[i-1]) & (2 ** left - 1)
			v2 = b64_alpha.index(unpadded[i]) >> (left - 2)
			v  = v1 << (8 - left) | v2
			decoded += chr(v)
			left -= 2
	return decoded

def reload():
	gdb.execute("target exec magic")
	command = "r" 
	gdb.execute(command,to_string=True)

def kill():
	gdb.execute("kill")

def insertnewpw(fn,password):
	fh = open(fn,"w")
	fh.write(password)
	fh.close()

def replace_str_index(text,index=0,replacement='',size=1):
    return '%s%s%s'%(text[:index],replacement,text[index+size:])

def setbp(address):
	command = "b *"+address
	gdb.execute(command,to_string=False)

def getmemory(address):
	command = "x "+ address	
	return gdb.execute(command,to_string=True)

def getmemorybysize(address,size):
	command = "x/"+str(size)+"xb "+ address	
	return gdb.execute(command,to_string=True)

def getregister(reg):
	command = "p/x $"+ reg	
	return gdb.execute(command,to_string=True)


def writeregister(reg,value):
	command = "set ($+"+reg+")="+value
	gdb.execute(command,to_string=True)

def dumpmem(address,size):
	start_addr = str(address)
	end_addr = str(address+size)
	command = "dump binary memory 605100.bin 0x" + start_addr + " 0x" + end_addr
	gdb.execute(command,to_string=True)

def getlo(arg):
	lobyte =  arg & 0x00FF
	return chr(lobyte)
	

gdb.execute("set confirm off")

#set breakpoint at 0x403B28 (just after fgets)
address = "0x403B28"
setbp(address)

#set rax to anticipated password before continue

password = "initpw"
insertnewpw(password,"a")

#start magic
reload()

#dump memory size = 0x2520bytes starting from 605100
#spacing between each structure is exactly 0xF0 bytes
# 55 0C 40 00 | 00 00 00 00 | 47 01 00 00 | 02 00 00 00
# function    |             | size        | offset	
# 03 00 00 00 | 25 00 00 00 | 5A 38 61 00 | 00 00 00 00
# num_chars   |             |             |
# C5 38 90 90 | 76 2F 06 12 | 2D CE 7B 28 | E4 B9 C9 0E
# expected    | expected    | expected    | expected
# E2 C7 35 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00
# expected    |




#327=0x147 FIBONACCI
#179=0xB3  CRC32
#766=0x2FE RC4
#806=0x326 B64
#143=0x8F  OFFSET13
#124=0x7C  EXACT_MATCH
#132=0x84  XOR
functionsize_signatures = [
    "327",
    "179",
    "766",
    "806",
    "143",
    "124",
    "132"
]

mem_password_addr = str(getregister("rax")).rstrip().split()[2]
found_password = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
gdb.execute("set {char [70]}" + mem_password_addr + " = \"" + found_password + "\"\n")
#open and read 605100.bin

#size_offset 	= 8
#expected_offset= 32
#offset_offset	= 12
#numchars_offset= 16 
while True:
	command = "dump binary memory 605100.bin 0x605100 0x607620"
	gdb.execute(command,to_string=True)
	mem_password_addr = str(getregister("rax")).rstrip().split()[2]

	#gdb.write("password in memory "+mem_password_addr+"\n")
	#mem_password = str(getmemorybysize(mem_password_addr,69))
	#gdb.write(mem_password+"\n")
	with open("605100.bin", "rb") as f:
		stt_offset = 0
		for i in range(0,33):
			#gdb.write("current stt_offset="+str(stt_offset)+"\n")		
			f.seek(stt_offset+8)
			fnsize = int.from_bytes(f.read(4), byteorder=sys.byteorder)
			fn = functionsize_signatures.index(str(fnsize))
			offset = int.from_bytes(f.read(4), byteorder=sys.byteorder)
			numchar = int.from_bytes(f.read(4), byteorder=sys.byteorder)	
			f.seek(12,1)
			#gdb.write("fn is..."+str(fn)+"\n")
			#gdb.write("fn is..."+str(fnsize)+"\n")
			if fn==0:
				#FIB
				#gdb.write("doing FIBONACCI...\n")
				for c in range(0,numchar):
					expected_value = hex(int.from_bytes(f.read(8), byteorder=sys.byteorder))
					expected_value = str(expected_value)[2:]
					#gdb.write(str(expected_value)+"\n")
					with open("fib_dict", "r") as fib:
						content = fib.readlines()
						line = [x for x in range(len(content)) if expected_value in content[x].lower()]
						char_found = chr(line[0]+31)
						found_password = replace_str_index(found_password,offset,char_found,1)
						offset+=1	
			elif fn==1:
				#CRC32
				#gdb.write("doing CRC32...\n")
				for c in range(0,numchar):
					expected_value = hex(int.from_bytes(f.read(4), byteorder=sys.byteorder))
					expected_value = str(expected_value)[2:]
					#gdb.write(str(expected_value)+"\n")
					if expected_value=="c55cd5b6":
						char_found = "ace"
						found_password = replace_str_index(found_password,offset,char_found,3)
						break
					else:
						with open("crc_dict", "r") as fib:
							content = fib.readlines()
							line = [x for x in range(len(content)) if expected_value in content[x].lower()]
							char_found = chr(line[0]+32)
							found_password = replace_str_index(found_password,offset,char_found,1)
							offset+=1	
			elif fn==2:
				#RC4
				#gdb.write("doing RC4...\n")
				expected_value = hex(int.from_bytes(f.read(numchar), byteorder="big"))
				expected_value = str(expected_value)[2:]
				#gdb.write(str(expected_value)+"\n")
				char_found = decrypt(expected_value)
				found_password = replace_str_index(found_password,offset,char_found,numchar)
			elif fn==3:
				#B64
				#gdb.write("doing Base64...\n")
				expected_value = hex(int.from_bytes(f.read(1), byteorder=sys.byteorder))
				expected_value = str(expected_value)[2:]
				#gdb.write(str(expected_value)+"\n")
				KEY_HEX = "2A395F64C2A74623536B7447284D70424925526a6238404a694544592d312450677954214c7671662b63686d51574f30654e5a34756e336c3748263277617a4b56"
				KEY = [KEY_HEX[k:k+2] for k in range(0, len(KEY_HEX), 2)]			
				POSITION = KEY.index(expected_value)
				if (numchar==1):
					char_found = chr((POSITION) * 4)
					found_password = replace_str_index(found_password,offset,char_found,1)
				else:
					char_found = " yo"
					found_password = replace_str_index(found_password,offset,char_found,3)
			elif fn==4:
				#OFFSET13
				#gdb.write("doing OFFSET13...\n")
				for c in range(0,numchar):
					expected_value = int.from_bytes(f.read(1), byteorder=sys.byteorder)
					char_found=chr(expected_value-13)
					#gdb.write(char_found+"\n")
					found_password = replace_str_index(found_password,offset,char_found,1)
					offset+=1
			elif fn==5:
				#EXACT_MATCH
				#gdb.write("doing EXACT_MATCH...\n")
				for c in range(0,numchar):
					expected_value = int.from_bytes(f.read(1), byteorder=sys.byteorder)
					char_found=chr(expected_value)
					#gdb.write(char_found+"\n")
					found_password = replace_str_index(found_password,offset,char_found,1)
					offset+=1
			elif fn==6:
				#XOR
				#gdb.write("doing XOR...\n")
				for c in range(0,numchar):
					expected_value = int.from_bytes(f.read(1), byteorder=sys.byteorder)
					char_found=chr(expected_value^0x2A)
					#gdb.write(char_found+"\n")
					found_password = replace_str_index(found_password,offset,char_found,1)
					offset+=1
			#gdb.write("updated pw = "+found_password+"\n")
			stt_offset+=0x30+0xF0
	
	#insertnewpw(password,found_password)
	gdb.write("updated pw = "+found_password+"\n")
	gdb.execute("set {char [70]}" + mem_password_addr + " = \"" + found_password + "\"\n")
	mem_password = str(getmemorybysize(mem_password_addr,70))
	gdb.write(mem_password+"\n")
	gdb.execute("c")
