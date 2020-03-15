from hashlib import sha1
import os, sys, getpass, time

from exploited import isPwned, get_line_length

def read_cfg():
    cfg_filename = os.environ['APP_CONFIG']
    dirname = os.path.dirname(os.path.realpath(cfg_filename))
    full_path = os.path.join(dirname, cfg_filename)
    with open(full_path) as f:
        return f.readline().strip().replace('\r','').replace('\n','')

if __name__ == '__main__':

    """ kick off the shindig with the command line args"""
    if len(sys.argv) == 1:
        string_to_hash = getpass.getpass("Enter password to be hashed using sha1\n>:~/$")
    else:
        print "User must specifiy an action."

    file_path = "/home/arabenjamin/.space/station/pwned-passwords-sha1-ordered-by-hash-v5.txt"
  
    
    HASH_HEX = sha1(str(string_to_hash)).hexdigest().upper()
  
    """ get the target file size"""
    fileSize = os.path.getsize(file_path)
    print "File sixe: ",fileSize
    print "Hash", str(HASH_HEX)

    # get the length of th file
    LINE_LENGTH = get_line_length(file_path)
    maxlines = fileSize / LINE_LENGTH
    index_range = (0,maxlines)
    line_index = maxlines/2 
    with open(file_path,'rb+') as f:
        try:
            isPwned(f, HASH_HEX, LINE_LENGTH, line_index, index_range)
        except ValueError as e:
            print e
