from urllib.request import urlopen
import unittest

class webpage_open_testing(unittest.TestCase):

    def test_webpage(self):
        url = 'https://ubiquitous-sniffle-y217w7w.pages.github.io/#/'
        resp = urlopen(url)
        code = resp.getcode()   
        self.assertEqual(200, code)


if __name__ == '__main__':
    unittest.main()