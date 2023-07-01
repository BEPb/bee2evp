
# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2021.02.18
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import logging
import subprocess
import os
import signal
from os.path import expanduser
home = expanduser("~")


# os.environ['OPENSSL_CONF'] = home + '/usr/local/openssl.cnf'
# OPENSSL_EXE_PATH = home + '/usr/local/bin/openssl'

os.environ['OPENSSL_CONF'] = '/usr/lib/ssl/openssl.cnf'
# OPENSSL_EXE_PATH = '/usr/bin/openssl'
OPENSSL_EXE_PATH = '/usr/local/bin/openssl'

logging.basicConfig(filename='openssl.log', level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] %(message)s')

def openssl(cmd, prefix='', echo=False, type_=0):
def openssl(cmd, prefix='', echo=False, type_=0):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, cmd)
	if echo:
		print(cmd)
	logging.debug('cmd OpenSSL: %s', cmd)
	if (type_ == 0):
		p = subprocess.Popen(cmd,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						stdin=subprocess.PIPE,
						shell=True)

		out, err_out = p.communicate()
		retcode = p.poll()

		logging.debug('status OpenSSL: %d', retcode)
		logging.debug('cmd OpenSSL (stdout): %s', out)
		logging.debug('cmd OpenSSL (stderr): %s', err_out)

		return retcode^1, out, err_out

	if (type_ == 1):
		p = subprocess.Popen(cmd,
						shell=True,
						preexec_fn=os.setsid)
		return p

	if (type_ == 2):
		out = subprocess.check_output(cmd,
						shell=True)
		return out
