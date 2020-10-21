'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



#!/usr/bin/env python3


import json
import sys
import re

data = open(sys.argv[1]).read()
# print(data)

applications = {}
for app in re.findall(
    r'\d+:{.*?}',
    re.search(
        'applications:{(.*?)}}',
        data).group(1)):
    foo = re.search('(.+):{name:\"(.*?)\"', app)
    # print(app)
    applications[foo.group(1)] = foo.group(2)

categories = {}
for cat in re.findall(
    r'\d+:{.*?}',
    re.search(
        'categories:{(.*?})}',
        data).group(1)):
    foo = re.search('(.+):{name:\"(.*?)\"', cat)
    # print(cat)
    categories[foo.group(1)] = foo.group(2)

print(json.dumps({"categories": categories, "applications": applications}))
