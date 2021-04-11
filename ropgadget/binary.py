## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

from binascii import unhexlify

from ropgadget.loaders.elf import *
from ropgadget.loaders.macho import *
from ropgadget.loaders.pe import *
from ropgadget.loaders.raw import *
from ropgadget.loaders.universal import *


class Binary(object):
    def __init__(self, options):
        self.__fileName  = options.binary
        self.__rawBinary = None
        self.__binary    = None

        try:
            fd = open(self.__fileName, "rb")
            self.__rawBinary = fd.read()
            fd.close()
        except:
            print("[Error] Can't open the binary or binary not found")
            return None

        if options.rawArch and options.rawMode:
            self.__binary = Raw(
                self.__rawBinary,
                options.rawArch,
                options.rawMode,
                options.rawEndian,
            )
        else:
            for loader in [ELF, PE, UNIVERSAL, MACHO]:
                if loader.isMatch(self.__rawBinary):
                    self.__binary = loader(self.__rawBinary)
                    break
            else:
                print("[Error] Binary format not supported")
                return None

    def getFileName(self):
        return self.__fileName

    def getRawBinary(self):
        return self.__rawBinary

    def getBinary(self):
        return self.__binary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()

    def getEndian(self):
        return self.__binary.getEndian()

    def getFormat(self):
        return self.__binary.getFormat()
