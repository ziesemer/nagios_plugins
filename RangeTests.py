#!/usr/bin/env python

import unittest
from check_cisco_stack import Range, RangeValueError

class RangeTests(unittest.TestCase):
	
	@classmethod
	def setUpClass(cls):
		cls.doDebug = False
		cls.firstPrint = False
	
	def t(self, r, n, b):
		if(self.doDebug):
			if(not(self.firstPrint)):
				print
				self.firstPrint = True
			print("  Testing {0} with {1} is {2}...".format(r.str, n, b))
		self.assertEqual(r.test(n), b)
	
	def testExact(self):
		r = Range("10")
		self.t(r, 9, False)
		self.t(r, 10, True)
		self.t(r, 11, False)
		self.t(r, None, False)
	
	def testInclusive(self):
		r = Range("[10,20]")
		self.t(r, 9, False)
		self.t(r, 10, True)
		self.t(r, 11, True)
		self.t(r, 19, True)
		self.t(r, 20, True)
		self.t(r, 21, False)
	
	def testExclusive(self):
		r = Range("(10,20)")
		self.t(r, 9, False)
		self.t(r, 10, False)
		self.t(r, 11, True)
		self.t(r, 19, True)
		self.t(r, 20, False)
		self.t(r, 21, False)
	
	def testInfInclusive(self):
		r = Range("[,]")
		self.t(r, float("-inf"), True)
		self.t(r, 0, True)
		self.t(r, float("inf"), True)
	
	def testInfInclusiveStart(self):
		r = Range("[,10]")
		self.t(r, float("-inf"), True)
		self.t(r, 0, True)
		self.t(r, 10, True)
		self.t(r, float("inf"), False)
	
	def testInfInclusiveEnd(self):
		r = Range("[10,]")
		self.t(r, 9, False)
		self.t(r, 10, True)
		self.t(r, float("inf"), True)
	
	def testInfExclusive(self):
		r = Range("(,)")
		self.t(r, float("-inf"), False)
		self.t(r, -1, True)
		self.t(r, 0, True)
		self.t(r, 1, True)
		self.t(r, float("inf"), False)
	
	def testInclExcl(self):
		r = Range("[10,20)")
		self.t(r, 9, False)
		self.t(r, 10, True)
		self.t(r, 11, True)
		self.t(r, 19, True)
		self.t(r, 20, False)
		self.t(r, 21, False)
		
	def testExclIncl(self):
		r = Range("(10,20]")
		self.t(r, 9, False)
		self.t(r, 10, False)
		self.t(r, 11, True)
		self.t(r, 19, True)
		self.t(r, 20, True)
		self.t(r, 21, False)
	
	def testEmptyRangeError(self):
		with self.assertRaises(ValueError):
			Range("")
	
	def testOnlyCommaError(self):
		with self.assertRaises(RangeValueError):
			Range(",")
	
	def testTooManyValuesError(self):
		with self.assertRaises(RangeValueError):
			Range("[1,2,3]")
	
	def testInvalidStartError(self):
		with self.assertRaises(RangeValueError):
			Range("1,2]")
		with self.assertRaises(RangeValueError):
			Range("x1,2]")
		with self.assertRaises(RangeValueError):
			Range(",2]")
	
	def testInvalidEndError(self):
		with self.assertRaises(RangeValueError):
			Range("[1,2")
		with self.assertRaises(RangeValueError):
			Range("[1,2x")
		with self.assertRaises(RangeValueError):
			Range("[1,")
	
	def testBackwardsError(self):
		with self.assertRaises(RangeValueError):
			Range("[2,1]")

if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(RangeTests)
	unittest.TextTestRunner(verbosity=2).run(suite)
