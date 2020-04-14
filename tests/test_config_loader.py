import unittest
import env
import sys

from lib import configloader 
class TestJSONLoad(unittest.TestCase):

  def setUp(self):

    self.real_arm_json = "./json/arm-test.json"
    self.fail_arm_json = "./json/arm-tests.json"

  def test_load_success(self):
    '''
    '''
    print("[PASS-Test]")
    configloader.JSONLoad(self.real_arm_json).dump_config()


if __name__ == "__main__":
  unittest.main()
