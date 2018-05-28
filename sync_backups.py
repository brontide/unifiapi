#!/usr/bin/env python3

import unifiapi
from pathlib import Path

# MODIFY
dest_dir = Path('/enterpoop/backups/unifi')
delete_backups = False


print("Logging into controller")
c = unifiapi.controller()
s = c.sites['default']()
print("Getting backup listing")
backups = s.c_backups()

for backup in backups:
    full_file = dest_dir / Path(backup['filename'])
    if full_file.exists():
        stat = full_file.stat()
        if stat.st_size != int(backup['size']):
            print(f"{full_file} DOES NOT MATCH FILESIZE")
        else:
            print(f"{full_file} exists and is the right size")
            if delete_backups:
                backup.delete()
    else:
        print("Copying {} to {}".format(backup['filename'], full_file))
        try:
            full_file.write_bytes(backup.download().read())
        except:
            # Oops, delete file that could be only partly complete
            full_file.unlink()
