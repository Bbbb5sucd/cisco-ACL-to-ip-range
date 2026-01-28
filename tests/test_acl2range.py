import unittest

from acl2range import parse_acl_line


class TestAcl2Range(unittest.TestCase):
    def test_standard_acl(self):
        e = parse_acl_line("access-list 10 permit 192.168.1.0 0.0.0.255")
        self.assertIsNotNone(e)
        self.assertEqual(str(e.src.start), "192.168.1.0")
        self.assertEqual(str(e.src.end), "192.168.1.255")
        self.assertIsNone(e.dst)

    def test_extended_acl_any_dst(self):
        e = parse_acl_line("access-list 101 permit tcp 10.0.0.0 0.0.0.255 any eq 443")
        self.assertIsNotNone(e)
        self.assertEqual(e.protocol, "tcp")
        self.assertEqual(str(e.src.start), "10.0.0.0")
        self.assertEqual(str(e.src.end), "10.0.0.255")
        self.assertEqual(str(e.dst.start), "0.0.0.0")
        self.assertEqual(str(e.dst.end), "255.255.255.255")

    def test_named_acl_sequence(self):
        e = parse_acl_line("10 permit tcp any host 1.2.3.4 eq 22")
        self.assertIsNotNone(e)
        self.assertEqual(str(e.dst.start), "1.2.3.4")
        self.assertEqual(str(e.dst.end), "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
