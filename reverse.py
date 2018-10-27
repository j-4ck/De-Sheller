# long live deletehumanity
from capstone import *
import sys

try:
	f = sys.argv[1]
	arch = sys.argv[2]
	mode = sys.argv[3]
except:
	print 'Usage:\n\tpython %s <file.example> <architecture> <mode>\nExample:\n\tpython %s YourShell.asm x86 32'%(sys.argv[0],sys.argv[0])
	sys.exit()
shellcode = ''
try:
	lines = open(f, 'r').readlines()
except:
	print 'Unable to open: '+f
	sys.exit()
for l in lines:
	shellcode += l
arch = locals()['CS_ARCH_'+str(arch).upper()]
mode = locals()['CS_MODE_'+str(mode).upper()]
md = Cs(arch, mode)
for i in md.disasm(shellcode, 0x00):
	print '0x%x:\t%s\t%s'%(i.address, i.mnemonic, i.op_str)
