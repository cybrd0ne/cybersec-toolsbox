#!/usr/bin/env python3
#================================================================
#     Author          @pwneip
#     Date            1 Dec 2019
#
#     Custom wrapper that logs all curl requests
#================================================================

import logging
import sys
from subprocess import call
from os import environ, uname
from time import gmtime

if 'SUDO_USER' in environ.keys():
    user = environ["SUDO_USER"]
else:
    user = environ["USER"]

log_file = environ["HOME"] + "/.curl.log"

logging.basicConfig(level=logging.DEBUG, filename=log_file, filemode="a+", 
    format="%(asctime)s " + uname()[1] + " - " + user + " - %(message)s", 
    datefmt='%Y-%m-%dT%H:%M:%SZ -')

logging.Formatter.converter = gmtime

logger = logging.getLogger("tool_logger")

logger.debug("curl " + ' '.join(sys.argv[1:]))

call(['curl']+sys.argv[1:]) #direct to curl to bypass alias
