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

def btls_client_cert(client_log_file, curve, ciphersuite):
	cmd = ('s_client -connect localhost:2023 -cipher {} -tls1_2 2>{}'.format(ciphersuite, client_log_file))
	openssl(cmd, prefix='echo test_{}={} |'.format(curve, ciphersuite), type_=2)


def main():
	tmpdirname = tempfile.mkdtemp()
	client_log_file = os.path.join(tmpdirname, 'c_log.txt')
	curve = 'bign-curve256v1'
	ciphersuite = 'DHE-BIGN-WITH-BELT-DWP-HBELT'
	btls_client_cert(client_log_file, curve, ciphersuite)

if __name__ == '__main__':
	main()
