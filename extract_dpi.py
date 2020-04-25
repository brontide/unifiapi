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
