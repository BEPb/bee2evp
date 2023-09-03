import socket
import ssl
from openssl import openssl
import os
from bign import *
import tempfile

def btls_gen_privkey(privfile, curve):
	cmd = 'genpkey -engine bee2evp -algorithm bign -pkeyopt params:{} -out {}'.format(curve, privfile)
	print(cmd)
	retcode, block, er__ = openssl(cmd)
	print(retcode)
	print(block)
	print(er__)


def btls_issue_cert(privfile, certfile):
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY/ST=MINSK" -new -key {} -nodes -out {}'.format(privfile, certfile))
	print(cmd)
	retcode, block, er__ = openssl(cmd)
	print(retcode)
	print(block)
	print(er__)

def main():
	tmpdirname = tempfile.mkdtemp()
	server_log_file = os.path.join(tmpdirname, 's_log.txt')
	curve = 'bign-curve256v1'
	priv = os.path.join(tmpdirname, '{}.key'.format(curve))
	btls_gen_privkey(priv, curve)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv, cert)
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile=cert, keyfile=priv)

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(('172.18.0.3', 2023))
		s.listen()
		print("Start")


		with context.wrap_socket(s, server_side=True) as wrapped_socket:
			conn, addr = wrapped_socket.accept()
			print('Connected by', addr)

			with open('file.txt', 'rb') as f:
				data = f.read()
				conn.sendall(data)

	finally:
		s.close()

if __name__ == '__main__':
	main()
