import os
import sys
import time
import string
import random
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
from random import randint, choice

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def quotes():
    '''
    Om de spanningsboog vast te houden

    '''
    _quotes = [
        '"The path to success is to take massive, determined action." ~ Tony Robbins',
        '"Kicking ass takes getting your ass kicked" ~ Jason Calacanis',
        '"The perfect is the enemy of the good." ~ Voltaire',
        '"Words may show a man\'s wit but actions his meaning." ~ Benjamin Franklin',
        '"If you love life, don\'t waste time, for time is what life is made up of." ~ Bruce Lee',
        '"In essence, if we want to direct our lives, we must take control of our consistent actions. It\'s not what we do once in a while that shapes our lives, but what we do consistently." ~ Tony Robbins',
        '"Success comes from taking the initiative and following up persisting eloquently expressing the depth of your love. What simple action could you take today to produce a new momentum toward success in your life?" ~ Tony Robbins',
        '"If you spend too much time thinking about a thing, you\'ll never get it done. " ~ Bruce Lee',
        '"The less effort, the faster and more powerful you will be. " ~ Bruce Lee',
        '"Most people have no idea of the giant capacity we can immediately command when we focus all of our resources on mastering a single area of our lives." ~ Tony Robbins',
        '"Focus is a matter of deciding what things you are not going to do" ~ John Carmack',
        '"In order to succeed, people need a sense of self-efficacy, to struggle together with resilience to meet the inevitable obstacles and inequities of life." ~ Albert Bandura',
        '"Only to the extent that we expose ourselves over and over to annihilation can that which is indestructible in us be found." ~ Pema Chodron',
        '"The vision must be followed by the venture. It is not enough to stare up the steps - we must step up the stairs." ~ Vance Havner',
        '"Whatever you can do, or dream you can do, begin it. Boldness has genius, power and magic in it. Begin it now." ~ Goethe',
        '"Wij zijn de Borg. Wij zullen uw biologische en technologische eigenschappen aan de onze toevoegen. Uw samenleving wordt aangepast om de onze te dienen. Verzet is zinloos." ~ De Borg',
        '"Bezit is diefstal." ~ Het proletariaat',
        '"incompetente prutsers" ~ Visser'
    ]
    return str(choice(_quotes))


# auto_int
def auto_int(x):
    return int(x, 0)

def lezen(bestand):
    # bestandjes lezen
    file = open(bestand, 'rb')
    item = file.read()
    file.close()
    return item.decode()

def rlezen(bestand):
    # bestandjes lezen
    file = open(bestand, 'rb')
    item = file.read()
    file.close()
    return item

def schrijven(bestand, code):
    # bestandjes schrijven
    file = open(bestand, 'w')
    item = file.write(code)
    file.close()

def bschrijven(bestand, code):
    # bestandjes schrijven
    file = open(bestand, 'wb')
    item = file.write(code)
    file.close()

def xor(wat, sleutel):
    for i, byte in enumerate(wat):
        byteInt = int(byte, 16)
        byteInt = byteInt ^ sleutel
        wat[i] = "{0:#0{1}x}".format(byteInt,4)
    return wat