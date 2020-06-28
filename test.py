from hashlib import sha1
import unittest, os

from compromised import isPwned, get_line_length, read_cfg



class Test_findHash(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):

        self.secret = 'password@1234'
        self.TARGET_HASH = sha1(self.secret+'salt').hexdigest().upper()
        self.file_path = "test_passwords_sha1.txt"
        
        """ get the target file size"""
        self.fileSize = os.path.getsize(self.file_path)
        self.LINE_LENGTH = get_line_length(self.file_path)
        self.total_lines = self.fileSize / self.LINE_LENGTH

        pass

    def tearDown(self):
        pass

    def test_readCfg(self):
        self.assertNotEqual(os.environ['APP_CONFIG'], True)
        self.assertNotEquals(read_cfg(), '')


    def hash_pass(self):

        return sha1(read_cfg()).hexdigest().upper()

    def test_recursive_search_pass(self):
        with open(self.file_path,'rb+') as f:
            
            # get the length of the file
            total_lines = self.fileSize / self.LINE_LENGTH
            index_range = (0, total_lines)
            line_index = self.total_lines/2 

            result = isPwned(f, self.hash_pass(), self.LINE_LENGTH, line_index, index_range)
            self.assertEqual(result, True)

    def test_recursive_search_fail(self):
        with open(self.file_path,'rb+') as f:
            
            # get the length of the file
            total_lines = self.fileSize / self.LINE_LENGTH
            index_range = (0, total_lines)
            line_index = self.total_lines/2 

            result = isPwned(f, self.TARGET_HASH, self.LINE_LENGTH, line_index, index_range)
            self.assertEqual(result, False)


        
        

if __name__ == '__main__':
    unittest.main()

    
    
    