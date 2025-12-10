#!/usr/bin/env python3
import logging, sys
from subprocess import call
from os import environ, uname
from time import gmtime
user = (environ["SUDO_USER"] if 'SUDO_USER' in environ.keys() else 
    environ["USER"])

log_file = environ["HOME"] + "/.curl.log"
logging.basicConfig(level=logging.DEBUG, filename=log_file, filemode="a+", 
    format="%(asctime)s " + uname()[1] + " - " + user + " - %(message)s", 
    datefmt='%Y-%m-%dT%H:%M:%SZ -')
logging.Formatter.converter = gmtime
logger = logging.getLogger("tool_logger")
logger.debug("curl " + ' '.join(sys.argv[1:]))
call(['curl']+sys.argv[1:])
