import sys, time, unittest
from unittest import *
from datetime import *

class CheckerResult:
    """
    Result of a single test.
    """
    
    def __init__(self):
        self.ok = False
        self.failed = False
        self.error = False
        self.exc = None
        self.desc = None
        self.start_time = 0
        self.end_time = 0

class Checker(TestResult):
    def __init__(self):
        TestResult.__init__(self)
        self.test_order = []
        self.tests = {}

    def results(self):
        """
        Return a list of CheckResult objects in the order the tests
        were fired.
        """
        r = []
        for t in self.test_order:
            r.append(self.tests[t])
        return r

    def addFailure(self, test, exc):
        """
        Called in case of test failures.  Failures are actual failures
        of tests.
        """
        self.tests[test].failed = True
        self.tests[test].exc = exc

    def addError(self, test, exc):
        """
        Called in case of errors.  Errors are exception happening in
        the test code.
        """
        self.tests[test].error = True
        self.tests[test].exc = exc

    def addSuccess(self, test):
        """
        Called when a test has completed successfully.
        """
        self.tests[test].ok = True

    def startTest(self, test):
        """
        Called before a test was started.

        Registers the test before in the local state database.
        """
        res = CheckerResult()
        self.test_order.append(test)
        self.tests[test] = res
        if test.__doc__:
            self.tests[test].desc = test.__doc__.strip()
        else:
            self.tests[test].desc = test.__class__
        self.tests[test].start_time = datetime.today()

    def stopTest(self, test):
        """
        Called at the time the test is stopped.
        """
        self.tests[test].end_time = datetime.today()

    def run(self, test):
        """
        Run a test suite.
        """
        test(self)
