#encoding: utf-8
import binascii
fn = open(r'./test.pcap', 'rb')
a = fn.read()
hexstr = binascii.b2a_hex(a)
print(hexstr[0:48])
print(hexstr[48:80])
print(hexstr[80:108])