import os
import sys
import time
import re
import platform
import argparse
import subprocess
import time
import xml.dom.minidom
import hashlib
import glob
import requests
import urllib3
import bs4 as bs
from random import randint

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# auto_int
def auto_int(x):
    return int(x, 0)