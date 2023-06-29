# *****************************************************************************
# \file bign.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over bign methods
# \created 2019.12.09
# \version 2020.02.27
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

from openssl import openssl
from settings import hex_encoder, b64_encoder, hex_decoder, b64_decoder

def bignStdParams(name, out_filename, specified=False, cofactor=False):
	options = '-pkeyopt params:{}'.format(name)
	if specified:
		options += ' -pkeyopt enc_params:specified'

	if cofactor:
		options += ' -pkeyopt enc_params:cofactor'

	cmd = 'genpkey -genparam -algorithm bign {} -out {}'.format(
		options, out_filename)
	retcode, out, er__ = openssl(cmd)
	return out

def bignGenKeypair(params_file, out_filename):
	cmd = 'genpkey -paramfile {} -out {}'.format(params_file, out_filename)
	retcode, out, er__ = openssl(cmd)
	return out

def bignCalcPubkey(private_key_file, out_filename):
	cmd = 'pkey -in {} -pubout -out {}'.format(private_key_file, out_filename)
	retcode, public_key, er__ = openssl(cmd)
	return public_key

def bignSign(prkey, hashname, src , dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -sign {} -out {}'.format(hashname, prkey, dest)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return retcode

def bignSign2(prkey, hashname, src, dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -sign {} -sigopt sig:deterministic -out {}'.format(
		hashname, prkey, dest)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return retcode

def bignVerify(prkey, hashname, src, sign_file):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -{} -prverify {} -hex -signature {}'.format(
		hashname, prkey, sign_file)
	retcode, out, er__ = openssl(cmd, prefix=prefix, echo=False)
	return out.decode()[:-1].strip()