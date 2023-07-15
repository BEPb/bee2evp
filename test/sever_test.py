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

def btls_gen_privkey(privfile, curve):
	cmd = 'genpkey -engine bee2evp -algorithm bign -pkeyopt params:{} -out {}'.format(curve, privfile)
	retcode, block, er__ = openssl(cmd)

def btls_issue_cert(privfile, certfile):
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY/ST=MINSK" -new -key {} -nodes -out {}'.format(privfile, certfile))
	retcode, block, er__ = openssl(cmd)

def btls_server_cert(tmpdirname, server_log_file, curve, psk=False):
	priv = os.path.join(tmpdirname, '{}.key'.format(curve))
	btls_gen_privkey(priv, curve)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv, cert)

	if psk:
		cmd = ('s_server -key {} -cert {} -tls1_2 -psk 123456 -psk_hint 123  >> {}'.format(priv, cert, server_log_file))
	else:
		cmd = ('s_server -key {} -cert {} -tls1_2 >> {}'.format(priv, cert, server_log_file))

	global server_cert
	server_cert = openssl(cmd, type_=1)

def btls_client_cert(client_log_file, curve, ciphersuites, psk=False):
	for ciphersuite in ciphersuites:
		if psk:
			cmd = ('s_client -cipher {} -tls1_2 -psk 123456 2>{}'.format(ciphersuite, client_log_file))
		else:
			cmd = ('s_client -cipher {} -tls1_2 2>{}'.format(ciphersuite, client_log_file))

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
	# curves_list = ['1.2.112.0.2.0.34.101.45.3.1', '1.2.112.0.2.0.34.101.45.3.2', '1.2.112.0.2.0.34.101.45.3.3']

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
	test_btls()
	if (fail == True):
		sys.exit(1)
