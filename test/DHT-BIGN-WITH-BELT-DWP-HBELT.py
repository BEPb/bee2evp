from settings import *
import sys, os, shutil
import signal
import tempfile
import threading
import time
from os.path import expanduser
from openssl import openssl

home = expanduser("~")
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


def btls_gen_privkey(privfile, curve):
	print('####### btls_gen_privkey start ##########')
	cmd = 'genpkey -algorithm bign -pkeyopt params:{} -out {}'.format(curve, privfile)
	retcode, block, er__ = openssl(cmd)
	print(retcode)
	print(block)
	print(er__)
	print('####### btls_gen_privkey end ##########')


def btls_issue_cert(privfile, certfile):
	print('####### btls_issue_cert start ##########')
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY/ST=MINSK" -new -key {} -nodes -out {}'.format(privfile, certfile))
	retcode, block, er__ = openssl(cmd)
	print(retcode)
	print(block)
	print(er__)
	print('####### btls_issue_cert end ########## \n')

def btls_server_cert(tmpdirname, server_log_file, curve, psk=False):
	print('####### btls_server_cert start ##########')
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
	print('####### btls_server_cert end ########## \n')

def btls_client_cert(client_log_file, curve, ciphersuites, psk=False):
	print('####### btls_client_cert start ##########')
	for ciphersuite in ciphersuites:
		if psk:
			cmd = ('s_client -cipher {} -tls1_2 -psk 123456 2>{}'.format(ciphersuite, client_log_file))
		else:
			cmd = ('s_client -cipher {} -tls1_2 2>{}'.format(ciphersuite, client_log_file))

		openssl(cmd, prefix='echo test_{}={} |'.format(curve, ciphersuite), type_=2)
	print('####### btls_client_cert end ########## \n')
def btls_server_nocert(server_log_file):
	print('####### btls_server_nocert start ##########')
	cmd = ('s_server -tls1_2 -psk 123456 -psk_hint 123 -nocert >> {}'
			.format(server_log_file))

	global server_nocert
	server_nocert = openssl(cmd, type_=1)
	print('####### btls_server_nocert end ########## \n')

def btls_client_nocert(client_log_file, curves_list, ciphersuites):
	print('####### btls_client_nocert start ##########')
	for ciphersuite in ciphersuites:
		for curves in curves_list:
			if curves != 'NULL':
				cmd = ('s_client -cipher {} -tls1_2 -curves {} -psk 123456 2>{}'
						.format(ciphersuite, curves, client_log_file))
			else:
				cmd = ('s_client -cipher {} -tls1_2 -psk 123456 2>{}'
						.format(ciphersuite, client_log_file))
			openssl(cmd, prefix='echo test_{}={} |'.format(curves, ciphersuite), type_=2)
	print('####### btls_client_nocert end ########## \n')

def test_btls():
	tmpdirname = tempfile.mkdtemp()
	server_log_file = os.path.join(tmpdirname, 's_log.txt')
	client_log_file = os.path.join(tmpdirname, 'c_log.txt')

	# curves list for test BDHE and BDHTPSK
	curves_list = ['bign-curve256v1', 'bign-curve384v1', 'bign-curve512v1']

	noPSK_cipherssuites = ['DHT-BIGN-WITH-BELT-DWP-HBELT']

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
	print('\n ****** End NO_PSK ****** \n')

	with open(server_log_file, 'r') as f:
		server_out = f.read()

	for ciphersuite in noPSK_cipherssuites:
		print(ciphersuite)
		for curves in curves_list:
			retcode = (server_out.find('test_{}={}'.format(curves, ciphersuite)) != -1)
			test_result('	{}'.format(curves), retcode)

	shutil.rmtree(tmpdirname)

if __name__ == '__main__':
	test_version()
	test_engine()
	test_btls()
	if (fail == True):
			sys.exit(1)
