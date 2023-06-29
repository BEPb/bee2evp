# *****************************************************************************
# \file settings.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Settings required for testing
# \created 2020.01.27
# \version 2020.02.02
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import codecs
from sys import platform

hex_encoder = codecs.getencoder('hex')
b64_encoder = codecs.getencoder('base64')
hex_decoder = codecs.getdecoder('hex')
b64_decoder = codecs.getdecoder('base64')

if platform.startswith('win32'):
	from ctypes import windll, Structure, c_short, c_ushort, byref

	SHORT = c_short
	WORD = c_ushort

	class COORD(Structure):
	  """struct in wincon.h."""
	  _fields_ = [
		("X", SHORT),
		("Y", SHORT)]

	class SMALL_RECT(Structure):
	  """struct in wincon.h."""
	  _fields_ = [
		("Left", SHORT),
		("Top", SHORT),
		("Right", SHORT),
		("Bottom", SHORT)]

	class CONSOLE_SCREEN_BUFFER_INFO(Structure):
	  """struct in wincon.h."""
	  _fields_ = [
		("dwSize", COORD),
		("dwCursorPosition", COORD),
		("wAttributes", WORD),
		("srWindow", SMALL_RECT),
		("dwMaximumWindowSize", COORD)]

	# winbase.h
	STD_INPUT_HANDLE = -10
	STD_OUTPUT_HANDLE = -11
	STD_ERROR_HANDLE = -12

	stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
	SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
	GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

	csbi = CONSOLE_SCREEN_BUFFER_INFO()
	GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
	DEFAULT_FG = csbi.wAttributes

	class bcolors:
		OKGREEN = 0x0002
		FAIL = 0x0004
		ENDC = DEFAULT_FG

	def print_colored(text, color):
		SetConsoleTextAttribute(stdout_handle, color)
		print(text)
		SetConsoleTextAttribute(stdout_handle, bcolors.ENDC)

else:
	if platform.startswith('linux'):
		class bcolors:
			OKGREEN = '\033[92m'
			FAIL = '\033[91m'
			ENDC = '\033[0m'

		def print_colored(text, color):
			print(color + text + bcolors.ENDC)
