# *****************************************************************************
# \file test.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Python tests for openssl[bee2evp]
# \created 2019.07.10
# \version 2021.03.18
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

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

fail = False
def test_result(test_name, retcode):
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
	block = hex_decoder('b194bac80a08f53b366d008e584a5de4')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	block = beltBlockEncr(bytes(block), bytes(key))
	res = hex_encoder(block)[0].decode() == '69cca1c93557c9e3d66bc3e0fa88fa6e'
	test_result('Block Encrypt', res)

	#A.4 Decrypt
	block = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	block = beltBlockDecr(bytes(block), bytes(key))
	res = hex_encoder(block)[0].decode() == '0dc5300600cab840b38448e5e993f421'
	test_result('Block Decrypt', res)
	
	#ECB (|X| = 384)
	#A.6 Encrypt
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltECBEncr(bytes(src), bytes(key))
	res = hex_encoder(dest)[0].decode() == (
		'69cca1c93557c9e3d66bc3e0fa88fa6e'
		'5f23102ef109710775017f73806da9dc'
		'46fb2ed2ce771f26dcb5e5d1569f9ab0')
	test_result('ECB Encrypt', res)

	#A.8 Decrypt	
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltECBDecr(bytes(src), bytes(key))
	res = hex_encoder(dest)[0].decode() == (
		'0dc5300600cab840b38448e5e993f421'
		'e55a239f2ab5c5d5fdb6e81b40938e2a'
		'54120ca3e6e19c7ad750fc3531daeab7')
	test_result('ECB Decrypt', res)

	#CBC (|X| = 384)
	#A.10 Encrypt
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCBCEncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'10116efae6ad58ee14852e11da1b8a74'
		'5cf2480e8d03f1c19492e53ed3a70f60'
		'657c1ee8c0e0ae5b58388bf8a68e3309')
	test_result('CBC Encrypt', res)

	#A.12 Decrypt
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	iv = hex_decoder('7ecda4d01544af8ca58450bf66d2e88a')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltCBCDecr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'730894d6158e17cc1600185a8f411cab'
		'0471ff85c83792398d8924ebd57d03db'
		'95b97a9b7907e4b020960455e46176f8')
	test_result('CBC Decrypt', res)

	#CFB (|X| = 384)
	#A.14 Encrypt
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCFBEncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'c31e490a90efa374626cc99e4b7b8540'
		'a6e48685464a5a06849c9ca769a1b0ae'
		'55c2cc5939303ec832dd2fe16c8e5a1b')
	test_result('CFB Encrypt', res)

	#A.15 Decrypt
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	iv = hex_decoder('7ecda4d01544af8ca58450bf66d2e88a')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltCFBDecr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'fa9d107a86f375ee65cd1db881224bd0'
		'16aff814938ed39b3361abb0bf0851b6'
		'52244eb06842dd4c94aa4500774e40bb')
	test_result('CFB Decrypt', res)

	#CTR (|X| = 384)
	#A.16
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCTREncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'52c9af96ff50f64435fc43def56bd797'
		'd5b5b1ff79fb41257ab9cdf6e63e81f8'
		'f00341473eae409833622de05213773a')
	test_result('CTR Encrypt', res)

	#MAC-256
	#A.18
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() == '2dab59771b4b16d0'
	test_result('MAC-256', res)

	#MAC-128
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	test_result('MAC-128', res)

	#MAC-192
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a37')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	test_result('MAC-192', res)

	#HMAC
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a37')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	test_result('HMAC', res)

	#HASH
	#A.25
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = beltHash(bytes(src))
	res = hex_encoder(hash_)[0].decode() == (
		'749e4c3653aece5e48db4761227742eb'
		'6dbe13f4a80f7beff1a9cf8d10ee7786')
	test_result('belt-hash', res)

	#Bash256
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash256Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	test_result('bash256', res)

	#Bash384
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash384Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	test_result('bash384', res)

	#Bash512
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash512Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	test_result('bash384', res)

def test_bign():
	# Create temporary directory for testing
	tmpdirname = tempfile.mkdtemp()
	# Gen params bign-curve256v1
	params256 = os.path.join(tmpdirname, 'params256v1.pem')
	bignStdParams('bign-curve256v1', params256)
	out = openssl('asn1parse -in {}'.format(params256))
	res = out[1].decode().find('bign-curve256v1') != -1
	test_result('Gen params bign-curve256v1', res)

	# Gen params bign-curve384v1
	params384 = os.path.join(tmpdirname, 'params384v1.pem')
	bignStdParams('bign-curve384v1', params384)
	out = openssl('asn1parse -in {}'.format(params384))
	res = out[1].decode().find('bign-curve384v1') != -1
	test_result('Gen params bign-curve384v1', res)

	# Gen params bign-curve512v1
	params512 = os.path.join(tmpdirname, 'params512v1.pem')
	bignStdParams('bign-curve512v1', params512)
	out = openssl('asn1parse -in {}'.format(params512))
	res = out[1].decode().find('bign-curve512v1') != -1
	test_result('Gen params bign-curve512v1', res)

	# Gen private key bign-curve256v1
	prkey256 = os.path.join(tmpdirname,'prkey256v1.pem')
	bignGenKeypair(params256, prkey256)
	out = openssl('asn1parse -in {}'.format(prkey256))
	res = (out[1].decode().find('bign-curve256v1') != -1 & out[1].decode()
	.find('bign-pubkey') != -1)
	test_result('Gen private key bign-curve256v1', res)

	# Gen private key G.1
	key = '1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269'
	asn1cnf = '''
	asn1 = SEQUENCE:SubjectPublicKeyInfo
	[SubjectPublicKeyInfo]
	version = INTEGER:0

	algorithm = SEQUENCE:AlgorithmIdentifier

	subjectPublicKey = FORMAT:HEX,OCTETSTRING:{}

	[AlgorithmIdentifier]
	algorithm = OBJECT:bign-pubkey

	parameters = OBJECT:bign-curve256v1
	'''.format(key)
	asn1_conf_file = os.path.join(tmpdirname, 'asn1_conf')
	with open(asn1_conf_file,'w') as f:
		f.write(asn1cnf)
	G1prkey256der = os.path.join(tmpdirname, 'G1prkey256.der')
	G1prkey256pem = os.path.join(tmpdirname, 'G1prkey256.pem')
	retcode, out, er__ = openssl(
		'asn1parse -genconf {} -out {}'.format(asn1_conf_file, G1prkey256der))
	openssl('pkey -inform DER -in {} -outform PEM -out {}'
	.format(G1prkey256der,G1prkey256pem))
	retcode, out, er__ = openssl('asn1parse -in {}'.format(G1prkey256pem))
	out = out.decode().strip()[out.decode().rfind('[HEX DUMP]:'):].split(':')[1]
	res = (out == key)
	test_result('Generate private key G.1', res)

	# Gen private key bign-curve384v1
	prkey384 = os.path.join(tmpdirname, 'prkey384v1.pem')
	bignGenKeypair(params384, prkey384)
	out = openssl('asn1parse -in {}'.format(prkey384))
	res = (out[1].decode().find('bign-curve384v1') != -1 & 
		out[1].decode().find('bign-pubkey') != -1)
	test_result('Gen private key bign-curve384v1', res)

	# Gen private key bign-curve512v1
	prkey512 = os.path.join(tmpdirname, 'prkey512v1.pem')
	bignGenKeypair(params512, prkey512)
	out = openssl('asn1parse -in {}'.format(prkey512))
	res = (out[1].decode().find('bign-curve512v1') != -1 & 
		out[1].decode().find('bign-pubkey') != -1)
	test_result('Gen private key bign-curve512v1', res)

	# Calc public key bign-curve256v1
	pubkey256 = os.path.join(tmpdirname, 'pubkey256v1.pem')
	bignCalcPubkey(prkey256, pubkey256)
	out = openssl('asn1parse -in {}'.format(pubkey256))
	res = (out[1].decode().find('bign-curve256v1') != -1 & 
		out[1].decode().find('bign-pubkey') != -1)
	test_result('Calc public key bign-curve256v1', res)

	# Calc public key G.1
	G1pubkey256 = os.path.join(tmpdirname, 'G1pubkey256v1.pem')
	bignCalcPubkey(G1prkey256pem, G1pubkey256)
	out = openssl('asn1parse -in {} -offset 28 -dump'.format(G1pubkey256))
	out = re.sub('[\s\n]', '', out[1].decode())
	matches = re.findall('[0-9A-Fa-f]{4}-[0-9A-Fa-f]+-*[0-9A-Fa-f]+', out)
	ans = ''
	for match in matches:
		items = match.split('-')
		for item in items[1:]:
			ans += item
	res = (ans[2:] == ('bd1a5650179d79e03fcee49d4c2bd5dd'
					  'f54ce46d0cf11e4ff87bf7a890857fd0'
					  '7ac6a60361e8c8173491686d461b2826'
					  '190c2eda5909054a9ab84d2ab9d99a90'))
	test_result('Calc public key G.1', res)

	# Calc public key bign-curve384v1
	pubkey384 = os.path.join(tmpdirname, 'pubkey384v1.pem')
	bignCalcPubkey(prkey384, pubkey384)
	out = openssl('asn1parse -in {}'.format(pubkey384))
	res = (out[1].decode().find('bign-curve384v1') != -1 & 
		out[1].decode().find('bign-pubkey') != -1)
	test_result('Calc public key bign-curve384v1', res)

	# Calc public key bign-curve512v1
	pubkey512 = os.path.join(tmpdirname, 'pubkey512v1.pem')
	bignCalcPubkey(prkey512, pubkey512)
	out = openssl('asn1parse -in {}'.format(pubkey512))
	res = (out[1].decode().find('bign-curve512v1') != -1 & 
		out[1].decode().find('bign-pubkey') != -1)
	test_result('Calc public key bign-curve512v1', res)

	# Calc dgst belt-hash
	src = hex_decoder('b194bac80a08f53b366d008e58')[0]
	signbelth = os.path.join(tmpdirname, 'signbelth.sign')
	retcode = bignSign(prkey256, 'belt-hash', bytes(src), signbelth)
	res = (retcode == 1)
	test_result('Calc dgst belt-hash', res)

	# Verify dgst belt-hash
	out = bignVerify(prkey256, 'belt-hash', bytes(src), signbelth)
	res = (out == 'Verified OK')
	test_result('Verify dgst belt-hash', res)

	# Calc deterministic dgst belt-hash
	src = hex_decoder('b194bac80a08f53b366d008e58')[0]
	dsignbelth = os.path.join(tmpdirname, 'dsignbelth.sign')
	retcode = bignSign(G1prkey256pem, 'belt-hash', bytes(src), dsignbelth)
	res = (retcode == 1)
	test_result('Calc deterministic dgst belt-hash', res)

	# Verify deterministic dgst belt-hash
	out = bignVerify(G1prkey256pem, 'belt-hash', bytes(src), dsignbelth)
	res = (out == 'Verified OK')
	test_result('Verify deterministic dgst belt-hash', res)

	shutil.rmtree(tmpdirname)

def test_belt_kwp_dwp():
	tmpdirname = tempfile.mkdtemp()
	params256 = os.path.join(tmpdirname, 'params256.pem')
	cmd = ('genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1'
		' -pkeyopt enc_params:specified -pkeyopt enc_params:cofactor -out')
	openssl('{} {}'.format(cmd, params256))

	kwp128 = os.path.join(tmpdirname, 'kwp128.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp128 -pass pass:root -out {}'
		.format(params256, kwp128))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp128))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-kwp128', retcode)

	kwp192 = os.path.join(tmpdirname, 'kwp192.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp192 -pass pass:root -out {}'
		.format(params256, kwp192))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp192))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-kwp192', retcode)

	kwp256 = os.path.join(tmpdirname, 'kwp256.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp256 -pass pass:root -out {}'
		.format(params256, kwp256))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp256))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-kwp256', retcode)

	dwp128 = os.path.join(tmpdirname, 'dwp128.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp128 -pass pass:root -out {}'
		.format(params256, dwp128))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp128))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-dwp128', retcode)

	dwp192 = os.path.join(tmpdirname, 'dwp192.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp192 -pass pass:root -out {}'
		.format(params256, dwp192))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp192))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-dwp192', retcode)

	dwp256 = os.path.join(tmpdirname, 'dwp256.pem') 
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp256 -pass pass:root -out {}'
		.format(params256, dwp256))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp256))
	out = out.decode()
	retcode = (out.find('valid') != -1)
	test_result('belt-dwp256', retcode)

	shutil.rmtree(tmpdirname)
def btls_gen_privkey(privfile, curve):
	cmd = 'genpkey -algorithm bign -pkeyopt params:{} -out {}'.format(curve, privfile)
	retcode, block, er__ = openssl(cmd)

def btls_issue_cert(privfile, certfile):
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY/ST=MINSK" -new -key {} -nodes -out {}'
		.format(privfile, certfile))
	retcode, block, er__ = openssl(cmd)

'''def btls_server256_nopsk(tmpdirname, server_log_file):
	priv256 = os.path.join(tmpdirname, 'priv256.key')
	btls_gen_privkey(priv256, 'bign-curve256v1')

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv256, cert)

	cmd = ('s_server -key {} -cert {} -tls1_2 >> {}'
			.format(priv256, cert, server_log_file))
	global server_nopsk
	server_nopsk = openssl(cmd, type_=1)'''

'''def btls_server_dhepsk(tmpdirname, server_log_file):
	priv256 = os.path.join(tmpdirname, 'priv256.key')
	btls_gen_privkey(priv256)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv256, cert)

	cmd = ('s_server -tls1_2 -psk 123456 -psk_hint 123 -nocert >> {}'
			.format(server_log_file))
	global server_dhepsk
	server_dhepsk = openssl(cmd, type_=1)'''

'''def btls_server_dhtpsk(tmpdirname, server_log_file):
	priv256 = os.path.join(tmpdirname, 'priv256.key')
	btls_gen_privkey(priv256)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv256, cert)

	cmd = ('s_server -tls1_2 -key {} -cert {} -psk 123456 -psk_hint 123  >> {}'
			.format(priv256, cert, server_log_file))
	global server_dhtpsk
	server_dhtpsk = openssl(cmd, type_=1)'''

'''def btls_server(tmpdirname, server_log_file, curves, psk=False, bdhtpsk=False):
	if bdhtpsk:
		cmd = ('s_server -tls1_2 -psk 123456 -psk_hint 123 -nocert >> {}'
				.format(server_log_file))
	else:
		priv = os.path.join(tmpdirname, '{}.key'.format(curves))
		btls_gen_privkey(priv)

		cert = os.path.join(tmpdirname, 'cert.pem')
		btls_issue_cert(priv, cert)

		if psk:
			cmd = ('s_server -tls1_2 -key {} -cert {} -psk 123456 -psk_hint 123  >> {}'
					.format(priv, cert, server_log_file))
		else:
			cmd = ('s_server -key {} -cert {} -tls1_2 >> {}'
					.format(priv, cert, server_log_file))
	
	global server
	server = openssl(cmd, type_=1)'''

def btls_server_cert(tmpdirname, server_log_file, curve, psk=False):
	priv = os.path.join(tmpdirname, '{}.key'.format(curve))
	btls_gen_privkey(priv, curve)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv, cert)

	if psk:
		cmd = ('s_server -key {} -cert {} -tls1_2 -psk 123456 -psk_hint 123  >> {}'
				.format(priv, cert, server_log_file))
	else:
		cmd = ('s_server -key {} -cert {} -tls1_2 >> {}'
				.format(priv, cert, server_log_file))

	global server_cert
	server_cert = openssl(cmd, type_=1)

def btls_client_cert(client_log_file, curve, ciphersuites, psk=False):
	for ciphersuite in ciphersuites:
		if psk:
			cmd = ('s_client -cipher {} -tls1_2 -psk 123456 2>{}'
					.format(ciphersuite, client_log_file))
		else:
			cmd = ('s_client -cipher {} -tls1_2 2>{}'
					.format(ciphersuite, client_log_file))

		openssl(cmd, prefix='echo test_{}={} |'.format(curve, ciphersuite), type_=2)

def btls_server_nocert(server_log_file):
	cmd = ('s_server -tls1_2 -psk 123456 -psk_hint 123 -nocert >> {}'
			.format(server_log_file))

	global server_nocert
	server_nocert = openssl(cmd, type_=1)

def btls_client_nocert(client_log_file, curves_list, ciphersuites):
	for ciphersuite in ciphersuites:
		for curves in curves_list:
			if curves != 'NULL':
				cmd = ('s_client -cipher {} -tls1_2 -curves {} -psk 123456 2>{}'
						.format(ciphersuite, curves, client_log_file))
			else:
				cmd = ('s_client -cipher {} -tls1_2 -psk 123456 2>{}'
						.format(ciphersuite, client_log_file))
			openssl(cmd, prefix='echo test_{}={} |'.format(curves, ciphersuite), type_=2)

def test_btls():
	tmpdirname = tempfile.mkdtemp()
	server_log_file = os.path.join(tmpdirname, 's_log.txt')
	client_log_file = os.path.join(tmpdirname, 'c_log.txt')

	# curves list for test BDHEPSK
	curves_list_bdhepsk = ['NULL', 'bign-curve256v1', 'bign-curve384v1', 'bign-curve512v1',
					'bign-curve256v1:bign-curve384v1:bign-curve512v1', 
					'bign-curve256v1:bign-curve512v1']

	# curves list for test BDHE and BDHTPSK
	curves_list = ['bign-curve256v1', 'bign-curve384v1', 'bign-curve512v1']

	noPSK_cipherssuites = ['DHE-BIGN-WITH-BELT-DWP-HBELT', 'DHE-BIGN-WITH-BELT-CTR-MAC-HBELT',
						   'DHT-BIGN-WITH-BELT-DWP-HBELT', 'DHT-BIGN-WITH-BELT-CTR-MAC-HBELT']
	bdhePSK_ciphersuites = ['DHE-PSK-BIGN-WITH-BELT-DWP-HBELT', 'DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT']
	bdhtPSK_ciphersuites = ['DHT-PSK-BIGN-WITH-BELT-DWP-HBELT', 'DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT']
	nocert_ciphersuites = bdhePSK_ciphersuites
	cert_ciphersuites = bdhtPSK_ciphersuites + noPSK_cipherssuites

	# test NO_PSK ciphersuites
	for curve in curves_list:
		s_nopsk = threading.Thread(target=btls_server_cert, 
						args=(tmpdirname, server_log_file, curve))
		s_nopsk.run()
		time.sleep(1)
		c_nopsk = threading.Thread(target=btls_client_cert, 
						args=(client_log_file, curve, noPSK_cipherssuites))
		c_nopsk.run()

		# kill openssl s_server
		os.killpg(os.getpgid(server_cert.pid), signal.SIGTERM)
	print('End NO_PSK')

	# test BDHTPSK ciphersuites
	for curve in curves_list:
		s_dhtpsk = threading.Thread(target=btls_server_cert, 
						args=(tmpdirname, server_log_file, curve, True))
		s_dhtpsk.run()
		time.sleep(1)
		c_dhtpsk = threading.Thread(target=btls_client_cert, 
						args=(client_log_file, curve, bdhtPSK_ciphersuites, True))
		c_dhtpsk.run()

		# kill openssl s_server
		os.killpg(os.getpgid(server_cert.pid), signal.SIGTERM)
	print('End BDHTPSK')

	# test BDHEPSK ciphersuites
	s_dhepsk = threading.Thread(target=btls_server_nocert, 
					args=(server_log_file,))
	s_dhepsk.run()
	time.sleep(1)
	c_dhepsk = threading.Thread(target=btls_client_nocert, 
					args=(client_log_file, curves_list_bdhepsk, bdhePSK_ciphersuites))
	c_dhepsk.run()

	# kill openssl s_server
	os.killpg(os.getpgid(server_nocert.pid), signal.SIGTERM)
	print('End BDHEPSK')

	with open(server_log_file, 'r') as f:
		server_out = f.read()

	for ciphersuite in cert_ciphersuites:
		print(ciphersuite)
		for curves in curves_list:
			retcode = (server_out.find('test_{}={}'.format(curves, ciphersuite)) != -1)
			test_result('	{}'.format(curves), retcode)

	for ciphersuite in nocert_ciphersuites:
		print(ciphersuite)
		for curves in curves_list_bdhepsk:
			retcode = (server_out.find('test_{}={}'.format(curves, ciphersuite)) != -1)
			test_result('	{}'.format(curves), retcode)

	shutil.rmtree(tmpdirname)

if __name__ == '__main__':
	test_version()
	test_engine()
	test_belt()
	test_bign()
	test_belt_kwp_dwp()
	test_btls()
	if (fail == True):
		sys.exit(1)