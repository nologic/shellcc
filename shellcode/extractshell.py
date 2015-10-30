import re
import argparse
import subprocess

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-o", "--object", type=str, required=True, help="specify object file")
	parser.add_argument("-s", "--shellcode", type=str, required=True, help="specify shellcode output file")
	parser.add_argument("--symbol", type=str, default="_start", help="specify object symbol (_start by default)")	

	args = parser.parse_args()

	hexregex = re.compile("[a-f0-9]+")
	twochars = re.compile("..")

	text = subprocess.Popen("otool -t %s | grep -v '__TEXT\|:'" % (args.object), 
		                    shell=True, stdout=subprocess.PIPE).stdout.read()

	text = [ [twochars.findall(item)[::-1] 
	             for item in line.replace('\t', ' ').split(' ') if (len(item) != 16 and hexregex.match(item))] 
	                  for line in text.split('\n')]

	data = subprocess.Popen("otool -s __TEXT __cstring %s | grep -v '__TEXT\|:'" % (args.object), 
		                    shell=True, stdout=subprocess.PIPE).stdout.read()

	data = [ [twochars.findall(item)[::-1] 
	             for item in line.replace('\t', ' ').split(' ') if (len(item) != 16 and hexregex.match(item))] 
	                  for line in data.split('\n')]

	text = bytearray.fromhex("".join(sum(sum(text, []), [])))
	data = bytearray.fromhex("".join(sum(sum(data, []), [])))

	fo = open(args.shellcode, "wb")
	fo.write(text)
	fo.write(data)
	fo.close()

if __name__ == "__main__":
	main()