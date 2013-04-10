#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Insertion Encoder - Python Language
# Copyright (C) 2013 Geyslan G. Bem, Hacking bits
#
#   http://hackingbits.com
#   geyslan@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
   insertion_encoder

   * encodes any sequence pattern of garbage insertion
       Eg: True Byte = b, Garbage Byte = x
	     bxbxb ...
	     xbbxx ...
	     xxxbb ... 


   # ./insertion_encoder.py -h
   # ./insertion_encoder.py -g f3 -p xxbbxb -e f1f1 -s $'\x31\xc9\xf7\xe1...\x80'

'''

import sys
import getopt
import string


def usage ():
    usage = """
  -g --garbage        Garbage Byte to be inserted (one byte in hex format)
                        Default is 3f
                        Eg. -g 2f
                            --garbage 2f

  -p --pattern        Pattern of insertion. Garbage = x; True Shellcode Byte = b
                        Default is xb
                        Eg. -p xxxbbxbb
                            -p xbbbxbbx
                            --pattern xxbxxbxx

  -e --end            End signature (two bytes in hex format)
                        Default is f1f1
                        Eg. -e f2f2
                            --end f1aa

  -s --shellcode      The shellcode to be encoded with the Garbage Insertion Byte
                        Eg. -s $'\\xcd\\x80'
                            --shellcode `printf "\\xcc\\x90"`

  -h --help           This help
"""
    print(usage)

def main():
    garbageByte = "3f"
    pattern = "xb"
    endSignature = "f1f1"
    shellcode = ""    

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hg:p:e:s:")
                
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit()

    hasShellcode = False

    for o, a in opts:


        if o in ("-h", "--help"):
            usage()
            sys.exit()

        elif o in ("-g", "--garbage"):
            if (len(a) != 2 or not all(h in string.hexdigits for h in a)):
                print("  Garbage has to be in hex format. Eg. -g 3f\n")
                sys.exit()            
            garbageByte = a
            
        elif o in ("-p", "--pattern"):
            if (len(a) < 2 or not "x" in a):
                print("  Pattern has to be at least two differents bytes. Eg. -p bx\n")
                sys.exit()
            pattern = a

        elif o in ("-e", "--end"):
            if (len(a) != 4 or not all(h in string.hexdigits for h in a)):
                print("  End signature has to be in hex format. Eg. -e f1f1\n")
                sys.exit()
            endSignature = a

        elif o in ("-s", "--shellcode"):
            shellcode = a.encode("utf_8", "surrogateescape")


    if (not shellcode):
        print("  Is necessary to inform a shellcode. Eg. -s $'\\xcd\\x80'\n")
        sys.exit()    

    if (int("0x" + garbageByte, 16) in bytearray(shellcode)):
        print("  The shellcode being processed contains the byte '0x" + garbageByte + "'. " \
              "Please choose another Gargage!\n")
        sys.exit()

    endfirst = int("0x" + endSignature[:-2], 16)
    endsecond = int("0x" + endSignature[-2:], 16)

    for x in range(len(shellcode)):
        if (endfirst == shellcode[x] and x < len(shellcode) - 1):
            if( endsecond == shellcode[x+1]):
                print("  The shellcode being processed contains the ordered bytes '" + \
                      hex(endfirst) + "' '" + hex(endsecond) + \
                      "'. Please choose other End Signature!\n")
                sys.exit()
    
    encoded = '"'
    encoded2 = ""
    encoded3 = '"'
    
    print("Insertion Shellcode Encoder")
    print("http://hackingbits.com")
    print("https://github.com/geyslan/SLAE.git")
    print("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\n")

    print("Encoded shellcode:")

    p = 0
    s = 0

    while 1:

        if (pattern[p] != "x" and pattern[p] != "b"):
            print("  Pattern invalid: " + pattern + "\n")
            print("  See the help.\n")
            sys.exit()

        if (pattern[p] == "x"):
            encoded += "\\x" + garbageByte
            encoded2 += "0x" + garbageByte + ","

        if (s < len(shellcode)):
            if (pattern[p] == "b"):
                encoded += "\\x%02x" % bytearray(shellcode)[s]            
                encoded2 += "0x%02x," % bytearray(shellcode)[s]            
                s += 1

        p += 1
        if (p == len(pattern)):
            p = 0
        
        if (s == len(bytearray(shellcode)) and p == 0):
            encoded2 = encoded2[:-1]
            break
    
    end = r"\x" + endSignature[:-2] + r"\x" + endSignature[-2:]
    encoded3 += r"\xeb\x1a\x5e\x8d\x3e\x31\xc9\x8b\x1c\x0e"
    encoded3 += r"\x41\x66\x81\xfb"
    encoded3 += end 
    encoded3 += r"\x74\x0f\x80\xfb"
    encoded3 += r"\x" + garbageByte
    encoded3 += r"\x74\xf0\x88\x1f\x47\xeb\xeb\xe8\xe1\xff"
    encoded3 += r"\xff\xff"
    encoded3 += encoded[+1:]
    encoded3 += end
    
    encoded += '"'
    encoded3 += '";'

    print()
    print(encoded)
    print()
    print(encoded2)
    print()
    print()
    print("Encoded shellcode with decoder built-in:\n")
    print(encoded3)
    print()
    
    print()
    print("Length before: %d" % len(bytearray(shellcode)))
    print("Length after: %d" % ((len(encoded) - 2) /4))
    print("Length with decoder: %d" % ((len(encoded3) - 2) /4))


if __name__ == "__main__":
    main()
