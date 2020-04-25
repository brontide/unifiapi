#!/usr/bin/env python

from unifiapi import controller
from time import sleep

my_profile = 'default'
my_site = 'default'

print("Connecting to controller")
c = controller(my_profile)
print("Connection to site {}".format(my_site))
s = c.sites[my_site]()
print("Fetching site settings")
settings = s.settings()
print("Disabling DPI")
settings['dpi']['enabled'] = False
settings['dpi'].update()
print("Sleeping 5 seconds")
sleep(5)
print("Re-enabling DPI")
settings['dpi']['enabled'] = True
settings['dpi'].update()
