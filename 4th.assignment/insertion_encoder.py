#!/usr/bin/python
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

   * encodes any pattern of garbage insertion
       Eg: True Byte = b, Garbage Byte = x
	     bxbxb ...
	     xbbxx ...
	     xxxbb ... 


   # ./insertion_encoder.py -h
   # ./insertion_encoder.py -g f3 -p xxbbxb -s $'\x31\xc9\xf7\xe1...\x80'

'''

import sys, getopt

def usage ():
    usage = """
  -g --garbage        Garbage Byte to be Inserted (One Byte)
                        Default is 3f
                        Eg. -g 2f
                            --garbage 2f

  -p --pattern        Pattern of Insertion. Garbage = x; True Shellcode Byte = b
                        Default is xb
                        Eg. -p xxxbbxbb
                            -p xbbbxbbx
                            --pattern xxbxxbxx

  -s --shellcode      The shellcode to be encoded with the Garbage Insertion Byte
                        Eg. -s $'\\xcd\\x80'
                            --shellcode `printf "\\xcc\\x90"`

  -h --help           This help
"""
    print(usage)

def main():
    garbageByte = "3f"
    pattern = "xb"
    shellcode = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hg:p:s:")
                
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
            if (len(a) != 2):
                print("  Garbage has to be one byte length. Eg. -g 3f\n")
                sys.exit()
            
        elif o in ("-p", "--pattern"):

            hasGarbage = False

            for x in a:
                if (x == "x"):
                    hasGarbage = True
                    break
           
            if (len(a) < 2 or hasGarbage == False):
                print("  Pattern has to be at least two differents bytes. Eg. -p bx\n")
                sys.exit()
                
            pattern = a

        elif o in ("-s", "--shellcode"):
            shellcode = a.encode("utf_8", "surrogateescape")
            hasShellcode = True

    if (hasShellcode == False):
        print("  Is necessary to inform a shellcode. Eg. -s $'\\xcd\\x80'")
        sys.exit()
        
        
    encoded = '"'
    encoded2 = ""

    print("Insertion Shellcode Encoder")
    print("http://hackingbits.com")
    print("https://github.com/geyslan/SLAE.git")
    print("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n")

    print("Encoded shellcode:")

    isEnd = False
    p = 0
    s = 0
    while not isEnd:

        if (pattern[p] != "x" and pattern[p] != "b"):
            print("  Pattern invalid: " + pattern + "\n")
            print("  See the help.\n")
            sys.exit()

        if (pattern[p] == "x"):
            encoded += "\\x" + garbageByte
            encoded2 += "0x" + garbageByte + ","

        if (pattern[p] == "b"):
            encoded += "\\x%02x" % bytearray(shellcode)[s]
            encoded2 += "0x%02x," % bytearray(shellcode)[s]
            s += 1

        p += 1
        if (p == len(pattern)):
            p = 0
        
        if (s == len(bytearray(shellcode))):
            encoded2 = encoded2[:-1]
            break

    encoded += '"'

    print()
    print(encoded)
    print()
    print(encoded2)
    print()

    print("Length before: %d" % len(bytearray(shellcode)))
    print("Length after: %d" % ((len(encoded) - 2) /4))


if __name__ == "__main__":
    main()
