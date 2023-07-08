from openssl import openssl
import subprocess
from belt import *
from bign import *
from settings import *
import sys, os, shutil
import signal
import tempfile
import re
import threading
import time
from os.path import expanduser
home = expanduser("~")

import traceback
from openssl import openssl
from settings import hex_encoder, b64_encoder, hex_decoder, b64_decoder

def beltBlockEncr(block, key):
	assert len(block) * 8 == 128
	print('block - ', block)
	print('key - ', key)

	plain = b64_encoder(block)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = len(key) * 4
	print('plain - ', plain)
	print('hex_key - ', key)
	print('key_bitlen', key_bitlen)

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'enc -e -engine bee2evp -belt-ecb{} -nosalt -nopad -e -K {}'.format(key_bitlen, key)
	print('prefix - ', prefix)
	print('cmd - ', cmd)
	retcode, block, er__ = openssl(cmd, prefix)
	print('retcode - ', retcode)
	print('block - ', block)
	print('er__ - ', er__)
	return block

fail = False
def test_result(test_name, retcode):
	global fail
	if(retcode == 1):
		sys.stdout.write(test_name + ': ')
		print_colored('success', bcolors.OKGREEN)
	else:
		sys.stdout.write(test_name + ': ')
		print_colored('fail', bcolors.FAIL)
		fail = True

def test_version():
	retcode, out, __ = openssl('version')
	test_result('version', retcode)
	print(out.decode())

def test_engine():
	retcode, out, er__ = openssl('engine -c -t bee2evp')
	test_result('engine', retcode)
	print(out.decode())

def test_belt():
	#Block (|X| = 128)
	#A.1 Encrypt
	print('data - b194bac80a08f53b366d008e584a5de4')
	block = hex_decoder('b194bac80a08f53b366d008e584a5de4')[0]
	print('hexblock - ', hex_decoder('b194bac80a08f53b366d008e584a5de4'))
	print('hexblock[0] - ', block)
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	print('hexkey - ', hex_decoder('e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6'))
	print('hexkey[0] - ', key)
	print(len('b194bac80a08f53b366d008e584a5de4'))
	print(len('e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6'))
	print('bytes_hex_block - ', bytes(block))
	print('bytes_hex_key - ', bytes(key))
	block = beltBlockEncr(bytes(block), bytes(key))
	print('encr_block - ', block)
	res = hex_encoder(block)[0].decode() == '69cca1c93557c9e3d66bc3e0fa88fa6e'
	print('hex_encoder - ', hex_encoder(block)[0].decode())
	print('res - ', res)
	test_result('Block Encrypt', res)

	#A.4 Decrypt
	block = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	block = beltBlockDecr(bytes(block), bytes(key))
	res = hex_encoder(block)[0].decode() == '0dc5300600cab840b38448e5e993f421'
	test_result('Block Decrypt', res)



if __name__ == '__main__':
	test_version()
	test_engine()
	test_belt()
	# test_bign()
	# test_belt_kwp_dwp()
	# test_btls()
	if (fail == True):
		sys.exit(1)
