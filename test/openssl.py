# *****************************************************************************
# \file openssl.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over openssl commmands
# \created 2019.07.10
# \version 2021.02.18
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import subprocess
import os
import signal
from os.path import expanduser
home = expanduser("~")

os.environ['OPENSSL_CONF'] = home + '/usr/local/openssl.cnf'
OPENSSL_EXE_PATH = home + '/usr/local/bin/openssl'

def openssl(cmd, prefix='', echo=False, type_=0):
	cmd = '{} {} {}'.format(prefix, OPENSSL_EXE_PATH, cmd)
	if echo:
		print(cmd)

	if (type_ == 0):
		p = subprocess.Popen(cmd,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						stdin=subprocess.PIPE,
						shell=True)

		out, err_out = p.communicate()
		retcode = p.poll()
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
