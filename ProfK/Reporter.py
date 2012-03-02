import Checker, traceback

class TestReporter:
    """
    Basic report.  This has to be subsclassed as it doesn't do
    anything.
    """

    def line(self):
        """
        Prepare a line.
        """
        for i in range(0, 70):
            self.out.write("-")
        self.out.write("\n")

    def header(self):
        """Header of the report."""
        self.out.write("%s\n" % self.title)
        self.line()

    def summary(self, test):
        pass

    def footer(self):
        """
        Footer of the report.
        """
        self.line()       
        
    def report(self):
        """
        Format the report by simply calling header, summary and footer
        in that order.
        """
        self.header()

        tests_results = self.checker.results()
        for tr in tests_results:
            self.summary(tr)

        self.footer()

    def __init__(self, out):
        self.out = out
        self.title = "NO TITLE GIVEN"

class MostlyPositiveTestReporter(TestReporter):
    """
    Report everything from the test.
    """
    
    def __init__(self, checker, out):
        TestReporter.__init__(self, out)
        self.checker = checker
        self.ntot = 0
        self.nsucc = 0
        self.nfail = 0
        self.nerr = 0

    def summary(self, test_result):
        def summary_display_exc(exc):
            (_, ex_msg, ex_tb) = test_result.exc
            self.out.write("Exception: %s\n" % ex_msg)
            tb = traceback.format_list(traceback.extract_tb(ex_tb))
            for tb_entry in tb:
                self.out.write("%s" % tb_entry)

        self.ntot += 1
        self.out.write("%s\n" % test_result.desc)

        delta = test_result.end_time - test_result.start_time
        mins = delta.seconds // 60.0
        rsecs = delta.seconds % 60
        usec = float(rsecs) + float(delta.microseconds) / 1000000.0
        tm = "%d minutes %.4f seconds\n" % (mins, usec)

        if test_result.ok:
            self.nsucc += 1
            self.out.write("\t\tOK in %s" % tm)
        elif test_result.failed:
            self.nfail += 1
            self.out.write("\t\tFAILED %s" % tm)
            (_, ex_msg, _) = test_result.exc
            self.out.write("\t\tReason: %s" % ex_msg)

        elif test_result.error:
            self.nerr += 1
            self.out.write("\t\tERROR %s" % tm)
            summary_display_exc(test_result.exc)
            
        self.out.write("\n")

    def footer(self):
        self.line()
        if self.nsucc == self.ntot:
            self.out.write("All tests succeeded.\n")
        else:
            tpl = (self.nsucc, self.ntot, self.nfail, self.nerr)
            self.out.write("Score: %d/%d (%d failure(s), %d error(s))" % tpl)
                
class NegativeTestReporter(MostlyPositiveTestReporter):
    """
    Report only failures.

    Won't display anything if all the test have passed.
    """
    
    def __init__(self, checker, out):
        MostlyPositiveTestReporter.__init__(self, checker, out)

    def summary(self, test_result):
        if test_result.failed or test_result.error:
            MostlyPositiveTestReporter.summary(self, test_result)

    def report(self):
        run = False
        test_results = self.checker.results()
        for tr in test_results:
            if tr.failed or tr.error:
                run = True
                break
        if run: MostlyPositiveTestReporter.report(self)
    
