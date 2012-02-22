#!/cygdrive/c/Python27/python.exe
#
# a crappy PDF parser/writer
#
# CREDIT: some of the filter code is from Didier Stevens
# http://blog.didierstevens.com/programs/pdf-tools/
#
# TODO:
#       -fix all of the unget() crap
#
import re
import sys
import os
import string
import getopt
import zlib
import binascii
import cStringIO
import argparse

######################

#debug print
dprint = lambda msg: None


# token types used by cToker and cParser
TOK_REG_WS = 0
TOK_REG_DL = 1
TOK_DELIM = 2

# indices of list returned by cToker.nextToken()
TTYPE = 0
TVAL = 1
TDELIM = 2

# PDF delimiters
D_COMMENT = "%"
D_DICTSTART = "<"
D_DICTEND = ">"
D_ARRAYSTART = "["
D_ARRAYEND = "]"
D_LITERALSTART = "("
D_LITERALEND = ")"
D_NAMESTART = "/"


#http://code.activestate.com/recipes/142812/
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def hexdump(src, length=8):
    N=0; result=''
    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(FILTER)
       result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
       N+=length
    return result

#
class cToker:

    #
    whitespace = "\x00\x09\x0a\x0c\x0d\x20"
    delims = "()<>[]{}/%"

    #
    def __init__(self, data):
        self.data = data
        self.dLen = len(data)
        self.index = 0

    #
    def isws(self, c):
        return string.find(self.whitespace, c) != -1

    #
    def isd(self, c):
        return string.find(self.delims, c) != -1

    #
    def curOffset(self):
        return self.index

    #
    def skipWS(self):
        for i in xrange(self.index, self.dLen):
            
            c = self.data[i]

            #
            if not self.isws(c):
                self.index = i
                return self.data[i-1]

    #
    def nextToken(self):

        cur = ""
        for i in xrange(self.index, self.dLen):
            
            c = self.data[i]

            #
            if self.isws(c):
                if cur != "":
                    self.index = i + 1
                    return [TOK_REG_WS, cur, c]
            elif self.isd(c):
                if cur != "":
                    self.index = i
                    return [TOK_REG_DL, cur, c]
                else:
                    self.index = i + 1
                    return [TOK_DELIM, c, c]
            else:
                cur += c

        return None

    #
    def getc(self):
        c = self.data[self.index]
        self.index += 1
        return c

    #
    def peek(self):
        return self.data[self.index]

    #
    def unget(self):
        self.index -= 1

    #
    def peekToken(self):
        tok = self.nextToken()
        if tok:
            dprint("Peeked %s" % tok)
            self.ungetToken(tok[TVAL])
        return tok[TVAL]

    #
    def ungetToken(self, tok):
        #we don't know how much whitespace we passed so...
        while True:
            self.index -= 1
            if self.data[self.index:self.index+len(tok)] == tok:
                break
            if self.index == 0:
                print "Fatal error, can't unget token [%s]" % (tok)
                sys.exit(1)

    # this is ugly, better to tell nextToken() to eat whitespace
    def readLine(self):
        tokens = []
        while True:
            t = self.nextToken()
            tokens.append(t[TVAL])
            c = self.skipWS()
            dprint("readline token [%s] delim [%s]" % (t[TVAL], t[TDELIM]))
            if t[TDELIM] == "\r" or t[TDELIM] == "\n" or c == "\r" or c == "\n":
                break

        return tokens

    #
    def skip(self, n):
        self.index += n

    #XXX not intuitive, but usually you call this after you have -1 in cTok
    def prev(self):
        return self.data[self.index-2]

    # XXX fix these two next functions
    def skipLine(self):
        for i in xrange(self.index, self.dLen):
            c = self.data[i]
            if c == '\n' or c == '\r':
                self.index = i
                self.skipEOL()
                return


    #
    def skipEOL(self):
        for i in xrange(self.index, self.dLen):
            
            c = self.data[i]
            if c != "\r" and c != "\n":
                dprint("Setting to [%s]" % c)
                self.index = i
                return

    #
    def readN(self, n):
        r = self.data[self.index:self.index+n]
        self.index += n
        return r


# parser states
LOOKING = 0
PARSE_OBJ = 1
PARSE_STREAM = 2
GOT_OBJ_NUM = 3
GOT_OBJ_GEN = 4


#
keywords = [ "xref", "startxref", "trailer" ]


#
class cXref:

    def __init__(self):
        self.startEnds = []
        self.refs = []
        self.lines = []

    #
    def parse(self, cTok):

        #kind of a cheat, will break on nonconforming files
        while True:
            t = cTok.readLine()
            dprint(t)
            if len(t) == 1 and t[0] == "trailer":
                dprint("Pushing back trailer")
                cTok.ungetToken(t[0])
                break
            elif len(t) == 2:
                self.startEnds.append((t[0], t[1]))
                self.lines.append(t)
            elif len(t) == 3:
                self.refs.append(t)
                self.lines.append(t)
            else:
                print("Parse error: nonconforming xref table %d tokens %s" % (len(t), t))


#
class cParser:

    #
    def __init__(self, data):
        self.data = data

    #
    def parseXref(self, cTok):
        dprint("parsing xref")
        xr = cXref()
        xr.parse(cTok)
        return xr

    #
    def parseStartXref(self, cTok):
        dprint("Parsing startxref")
        cTok.nextToken()
        return

    #
    def parseTrailer(self, cTok):
        #advance past any ws
        dprint("Parsing trailer")
        cTok.skipWS()
        dprint("Next %s" % cTok.peek())
        return self.parseDict(cTok)

    #
    def parseObj(self, oNum, oGen, oOffset, cTok):
        pObj = pdfObj(oNum, oGen, oOffset)

        dprint("\n####################\nParsing object %d, %d" % (oNum, oGen))

        #
        while True:

            t = cTok.nextToken()
            v = t[TVAL]

            if t[TTYPE] == TOK_DELIM:
                if v == D_DICTSTART and cTok.peek() == D_DICTSTART:
                    cTok.unget()
                    pObj.addDict(self.parseDict(cTok))
                elif v == D_ARRAYSTART:
                    cTok.unget()
                    pObj.addArray(self.parseArray(cTok))
                elif v == D_LITERALSTART:
                    cTok.unget()
                    pObj.lString = self.parseStr(cTok)
                    pObj.setStr()
                elif v == D_COMMENT:
                    dprint("Skipping comment in object")
                    cTok.skipLine()
                elif v == D_NAMESTART:
                    pObj.addName("/" + cTok.nextToken()[TVAL])
                else:
                    print "Parse error: unknown object token %s, %s" % (v, cTok.peek())
            else:
                if v == "stream":
                    #read the stream data
                    cTok.skipEOL()
                    pObj.sData = cTok.readN(long(pObj.dic["/Length"]))
                    pObj.setStream()
                elif v == "endstream":
                    pass
                elif v == "endobj":
                    break

        return pObj

    #token == (
    def parseStr(self, cTok):

        cTok.getc()
        nParens = 1
        val = "("
        
        while nParens != 0:
            c = cTok.getc()
            
            if c == "(" and cTok.prev() != "\\":
                nParens += 1
            elif c == ")" and cTok.prev() != "\\":
                nParens -= 1
            else:
                val += c

        val += ")"
        return val

    #token == <
    def parseHexStr(self, cTok):

        cTok.getc()
        val = "<"
        while True:
            c = cTok.getc()
            if c == ">":
                break;
            val += c

        if len(val) & 1:
            val += "0"

        val += ">"
        return val

    #token == <<
    def parseDict(self, cTok):
        cTok.skip(2)

        dic = {}
        k = ""
        
        while True:

            t = cTok.nextToken()
            v = t[TVAL]
            dprint("v is [%s], k is [%s]" % (v, k))

            #find the key first, always a name
            if k == "" and v != D_DICTEND:
                if v != D_NAMESTART:
                    dprint("Error parsing dict, key != /NAME (%s)" % v)
                k = "/" + cTok.nextToken()[TVAL]
                continue

            #we're reading a value if we're here

            #check for a delimiter
            if t[TTYPE] == TOK_DELIM:
                if v == D_NAMESTART:
                    dic[k] = "/" + cTok.nextToken()[TVAL]
                elif v == D_LITERALSTART:
                    cTok.unget()
                    dic[k] = self.parseStr(cTok)
                elif v == D_DICTSTART and cTok.peek() != D_DICTSTART:
                    cTok.unget()
                    dic[k] = self.parseHexStr(cTok)
                elif v == D_ARRAYEND:
                    break
                elif v == D_ARRAYSTART:
                    cTok.unget()
                    dic[k] = self.parseArray(cTok)
                elif v == D_DICTSTART and cTok.peek() == D_DICTSTART:
                    cTok.unget()
                    dic[k] = self.parseDict(cTok)
                elif v == D_DICTEND and cTok.peek() == D_DICTEND:
                    cTok.skip(1)
                    break
                dprint("setting dict[%s] = %s" % (k, dic[k]))
            else:
                #this can possibly be several values in a row, ie "/Pages 1 0 R"
                while True:
                    t = cTok.nextToken()
                    if t[TTYPE] == TOK_DELIM:
                        cTok.ungetToken(t[TVAL])
                        break
                    else:
                        v += " " + t[TVAL]
                dic[k] = v
                dprint("setting dict[%s] = %s" % (k, v))

            #reset key
            k = ""

        return dic

    #token == [
    def parseArray(self, cTok):

        val = []
        cTok.skip(1)

        dprint("Parsing array")

        while True:

            t = cTok.nextToken()
            v = t[TVAL]

            #check for a delimiter
            if t[TTYPE] == TOK_DELIM:
                if v == D_NAMESTART:
                    val.append("/" + cTok.nextToken()[TVAL])
                elif v == D_LITERALSTART:
                    cTok.unget()
                    val.append(self.parseStr(cTok))
                elif v == D_DICTSTART and cTok.peek() != D_DICTSTART:
                    cTok.unget()
                    val.append(self.parseHexStr(cTok))
                elif v == D_ARRAYEND:
                    break
                elif v == D_ARRAYSTART:
                    cTok.unget()
                    val.append(self.parseArray(cTok))
                elif v == D_DICTSTART and cTok.peek() == D_DICTSTART:
                    cTok.unget()
                    val.append(self.parseDict(cTok))
            else:
                #a number, boolean
                val.append(v)
                dprint("Appending array elem %s" % v)

        return val

    #
    def parse(self, pDoc):
        
        oOffset = 0
        cTok = cToker(self.data)
        state = LOOKING

        while True:

            #
            t = cTok.nextToken()
            if t == None:
                break
            
            delim = t[TTYPE] == TOK_DELIM
            val = t[TVAL]
            
            dprint("token %s" % val)

            if state == LOOKING:

                #skip comments
                if delim and val == "%":
                    if not pDoc.version:
                        peek = cTok.peekToken()
                        if peek.find("PDF-") != -1:
                            pDoc.version = peek
                    dprint("Skipping comment")
                    cTok.skipLine()
                elif not delim and val in keywords:    #keywords
                    if val == "xref":
                        pDoc.addXref(self.parseXref(cTok))
                    elif val == "startxref":
                        self.parseStartXref(cTok)
                    elif val == "trailer":
                        pDoc.addTrailer(self.parseTrailer(cTok))
                elif val.isdigit():   #start of object
                    oNum = long(val)
                    state = GOT_OBJ_NUM
                    oOffset = cTok.curOffset() - len(val) - 1
            elif state == GOT_OBJ_NUM:
                if val.isdigit():
                    oGen = long(val)
                    state = GOT_OBJ_GEN
                else:
                    "Parse error: waiting for obj gen in obj num state, got %s" % val
                    state = LOOKING
            elif state == GOT_OBJ_GEN:
                if val == "obj":
                    state = PARSE_OBJ
                    pDoc.addObj(self.parseObj(oNum, oGen, oOffset, cTok))
                    state = LOOKING
                else:
                    print "Parse error: waiting for obj in obj gen state, got %s" % val
                    state = LOOKING
            else:
                print "Parse error: unknown state %d" % val


#object types
OBJ_UNKNOWN = 0
OBJ_STREAM = 2
OBJ_DICT = 4
OBJ_ARRAY = 8
OBJ_STR = 16
OBJ_NAME = 32

#
class pdfObj:

    #
    def __init__(self, num, gen, off):
        self.num = num
        self.gen = gen
        self.offset = off
        self.dic = {}
        self.array = []
        self.oType = OBJ_UNKNOWN
        self.sData = ""
        self.name = ""
        self.properName = ""

    def setName(self):
        self.oType |= OBJ_NAME
        self.name += "-Name"
    
    def addName(self, name):
        self.properName = name
        self.setName()

    def setStr(self):
        self.oType |= OBJ_STR
        self.name += "-String"

    def setArray(self):
        self.oType |= OBJ_ARRAY
        self.name += "-Array"

    def addArray(self, ar):
        self.array = ar
        self.setArray()

    def setStream(self):
        self.oType |= OBJ_STREAM
        self.name += "-Stream"

    def isStream(self):
        return self.oType & OBJ_STREAM

    def setDict(self):
        self.oType |= OBJ_DICT
        self.name += "-Dictionary"

    def addDict(self, d):
        self.dic = d
        self.setDict()

    def getType(self):
        try:
            return self.dic["/Type"]
        except KeyError:
            return self.name

    def getSubtype(self):
        try:
            return self.dic["/Subtype"]
        except KeyError:
            return None

    #update the stream contents
    def updateStream(self, newStream):
        self.oType |= OBJ_STREAM
        self.sData = newStream
        print "Stream length was %d, now %d (%#x)" % (long(self.dic["/Length"]), len(newStream), len(newStream))
        self.dic["/Length"] = str(len(newStream))

    #
    def writeDict(self, dic):

        buf = "<<"
        for k,v in dic.iteritems():
            buf += " " + k
            if isinstance(v, str):
                buf += " " + v
            elif isinstance(v, list):
                buf += " " + self.writeArray(v)
            elif isinstance(v, dict):
                buf += " " + self.writeDict(v)

        buf += ">>"
        return buf

    #
    def writeArray(self, array):
        buf = "["
        for v in array:
            if isinstance(v, str):
                buf += " " + v
            elif isinstance(v, list):
                buf += " " + self.writeArray(v)
            elif isinstance(v, dict):
                buf += " " + self.writeDict(v)

        buf += "]"
        return buf

    #write object to a buffer
    def serialize(self):

        buf = ""
        
        #first the header
        buf += "%s %s obj\r\n" % (self.num, self.gen)

        #check type
        if self.oType & OBJ_DICT:
            buf += self.writeDict(self.dic)
        if self.oType & OBJ_ARRAY:
            buf += self.writeArray(self.array)
        if self.oType & OBJ_STREAM:
            buf += "stream\r\n" + self.sData + "\r\nendstream"
        if self.oType & OBJ_STR:
            buf += self.lString + "\r\n"
        if self.oType & OBJ_NAME:
            buf += self.properName + "\r\n"
        if self.oType == OBJ_UNKNOWN:
            print "Error: can't write an unknown object type!"
        
        buf += "\r\nendobj\r\n"

        return buf

    #
    def display(self, dumpStreams, unFilter):
        subtype = self.getSubtype()
        if subtype:
            print "obj %d %d, type %s subtype %s, offset %d" % (self.num, self.gen,
                                        self.getType(), subtype, self.offset)
        else:
            print "obj %d %d, type %s, offset %d" % (self.num, self.gen,
                                        self.getType(), self.offset)

        #
        if self.oType & OBJ_NAME:
            print self.properName

        if self.oType & OBJ_DICT:
            print "{"
            for k,v in self.dic.iteritems():
                print "\t%s -> %s" % (k, v)
            print "}"
        
        if self.oType & OBJ_ARRAY:
            print "["
            for i in self.array:
                print "\t%s " % (i),
            print "\n]"

        if (self.oType & OBJ_STREAM) and dumpStreams:
            print "Dumping object stream..."
            self.dumpStreams(unFilter)

    #run the stream through any filters/predictors so it can be written
    #out without any compression
    def unfilterAndUpdateStream(self):

        #first unpack the stream
        unpacked = self.unpackStream()

        #remove the filters from dictionary
        try:
            del self.dic["/Filter"]
        except KeyError:
            pass    #not all streams have filters
        
        self.updateStream(unpacked)

    #
    def unpackStream(self):

        sLen = self.dic["/Length"]
        sData = self.sData
        dprint("Stream data len %d, claimed len %s" % (len(sData), sLen))

        #if it has no filter, just return it
        try:
            filters = self.dic["/Filter"]
        except KeyError:
            return sData

        #filters can be a list or just a single filter string, make it a list
        if isinstance(filters, str):
            filters = [filters]
        filtered = sData

        #apply each filter sequentially
        for filt in filters:
            print("Passing stream through filter %s" % (filt))
            if filt in FILTERS:
                filtered = FILTERS[filt](filtered)
                dprint(hexdump(filtered, 16))

        #apply predictors
        try:
            #each DecodeParms is an array of dicts or a single dict
            parmArray = self.dic["/DecodeParms"]
            if type(parmArray) is dict:
                parmArray = [parmArray]
            for parm in parmArray:
                try:
                    predictor = int(parm["/Predictor"])
                    if predictor in PREDICTORS:

                        #determine the number of columns
                        #http://forums.adobe.com/thread/664902?tstart=0
                        cols = 1
                        bpc = 8
                        colors = 1
                        try:
                            cols = int(parm["/Columns"])
                            bpc = int(parm["/BitsPerComponent"])
                            colors = int(parm["/Colors"])
                        except KeyError:
                            pass
                        
                        nCols = (((cols * bpc * colors) + 7) / 8) + 1

                        filtered = PREDICTORS[predictor](filtered, nCols)
                        dprint("Passing stream through predictor %d" % (predictor))
                        dprint(hexdump(filtered, 16))
                except KeyError:
                    pass
        except KeyError:
            pass

        return filtered

    #
    def dumpStreams(self, unFilter):
        unpacked = self.unpackStream()
        print hexdump(unpacked, 16)
#
class pdfDoc:

    #
    hdr = "%PDF-1.6\n"
    
    
    #
    def __init__(self, infile):
        
        #
        self.xRefTables = []
        self.trailerDicts = []
        self.objs = []
        self.oMax = 0
        self.version = None
        
        #slurp file
        f = open(infile, "rb")
        self.data = f.read()
        f.close()

    #for now this just handles streams
    def extractObjects(self, objList):
        for o in self.objs:
            if o.num in objList:
                if o.isStream():
                    f = open("pdf-obj-%d.bin" % (o.num), "wb")
                    f.write(o.sData)
                    f.close()
                    print "Wrote out object %d" % (o.num)
                else:
                    print "Trying to unpack an object (%d) that isn't a stream" % (o.num)

    #
    def unpackStreams(self, unpackObjs):
        for o in self.objs:
            if o.num in unpackObjs:
                if o.isStream():
                    o.unfilterAndUpdateStream()
                else:
                    print "Trying to unpack an object (%d) that isn't a stream" % (o.num)

    #
    def parse(self):

        pParse = cParser(self.data)
        pParse.parse(self)

    #
    def display(self, dumpStreams, unFilter):
        if self.version:
            print "PDF version [%s]" % (self.version)
        else:
            print "Couldn't find PDF version"
        print "######################"
        print "Trailer dictionaries:"
        for t in self.trailerDicts:
            print "{"
            for k,v in t.iteritems():
                print "\t%s->%s" % (k, v)
            print "}"
        print "######################"

        print "Xref Tables:"
        for x in self.xRefTables:
            print "["
            for y in x.lines:
                print "\t", " ".join(y)
            print "]"

        print "~~~~~~~~~~~~~~~~~~~~~~~~"
        
        print "Objects:"
        for o in self.objs:
            print "------------------------------"
            o.display(dumpStreams, unFilter)

        print "------------------------------"

    #
    def addXref(self, xref):
        self.xRefTables.append(xref)

    #
    def addTrailer(self, trailer):
        self.trailerDicts.append(trailer)

    #
    def createObj(self):
        self.oMax += 1
        return pdfObj(self.oMax, 0, 0)
    #
    def addObj(self, obj):
        self.objs.append(obj)
        if obj.num > self.oMax:
            self.oMax = obj.num

    #
    def findObjs(self, fFilter):

        found = []
        for o in self.objs:
            if fFilter(o):
                found.append(o)
        
        return found

    #
    def getObjByNum(self, num):
        for o in self.objs:
            if o.num == num:
                return o
        return None

    #
    def emitPDF(self, outfile):

        of = open(outfile, "wb")

        xOffset = 0
        xrefs = []
        
        #write the header
        of.write(self.hdr)
        xOffset += len(self.hdr)
        
        #
        for o in self.objs:

            oData = o.serialize()
            oLen = len(oData)
            o.offset = xOffset
        
            #write out the object
            of.write(oData)
        
            #add the xref offset
            xrefs.append(xOffset)
        
            #update offset
            xOffset += oLen
        
            #check if it's the catalog
            if o.dic.has_key("/Type") and o.dic["/Type"] == "/Catalog":
                nRoot = o.num
        
        
        #
        xOffset += 2    #newlines
        
        #write out the XREF table
        xref =  "\n\nxref\n" + \
                "0 %d\n" % (self.oMax + 1) + \
                "0000000000 65535 f\r\n"
        
        #missing objects need to have lines
        for i in xrange(1, self.oMax + 1):
            o = self.getObjByNum(i)
            if o is not None:
                xref += "%010d 00000 n\r\n" % o.offset
            else:
                xref += "0000000000 00000 n\r\n"
        
        #emit the trailer
        trailer =   "trailer\n" + \
                    "<< /Size %d\n" % (self.oMax + 1) +  \
                    "/Root %d 0 R\n" % (nRoot) + \
                    ">>\n" + \
                    "startxref\n" + \
                    "%d\n" % xOffset + \
                    "%%EOF"
        
        of.write(xref)
        of.write(trailer)
        of.close()

        print "Created output file %s" % outfile


# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py
def ASCII85Decode(data):
  import struct
  n = b = 0
  out = ''
  for c in data:
    if '!' <= c and c <= 'u':
      n += 1
      b = b*85+(ord(c)-33)
      if n == 5:
        out += struct.pack('>L',b)
        n = b = 0
    elif c == 'z':
      assert n == 0
      out += '\0\0\0\0'
    elif c == '~':
      if n:
        for _ in range(5-n):
          b = b*85+84
        out += struct.pack('>L',b)[:n-1]
      break
  return out

def ASCIIHexDecode(data):
    return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))

def FlateDecode(data):
    return zlib.decompress(data)

def RunLengthDecode(data):
    f = cStringIO.StringIO(data)
    decompressed = ''
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
#    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed

#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions: 

class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in xrange(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return

####

def LZWDecode(data):
    return ''.join(LZWDecoder(cStringIO.StringIO(data)).run())

#decoders are borrowed from didier stevens pdf-parser.py
FILTERS = { "/ASCII85Decode":ASCII85Decode, "/ASCIIHexDecode":ASCIIHexDecode,
            "/FlateDecode":FlateDecode, "/RunLengthDecode":RunLengthDecode,
            "/LZWDecode":LZWDecode,
            }

# predictors

def pNone(data, nCols):
    return data

def pTIFF(data, nCols):
    print "TIFF predictor not implemented"
    return data

def pSUB(data, nCols):
    return pUpSubWorker(data, nCols, False)

def pUP(data, nCols):
    return pUpSubWorker(data, nCols, True)

def pUpSubWorker(data, nCols, up):

    #pad out data with 0's if it's not even
    dLen = len(data)
    nRows = dLen / nCols
    if dLen % nCols != 0:
        nRows += 1
        data += "\x00" * (dLen % nCols)

    #for mutability
    dList = list(data)

    # row 0 is already populated properly
    unpredicted = data[1:nCols]
    
    #simulate a 2d array
    for r in xrange(1, nRows):

        #col 0 contains the predictor type
        for c in xrange(1, nCols):
            #dprint("%#x + %#x" % (ord(dList[i]), ord(dList[i-nCols])))
            curIndex = (r * nCols) + c
            lastRowIndex = ((r - 1) * nCols) + c

            #do up/sub
            if up:
                dList[curIndex] = chr((ord(dList[curIndex]) + ord(dList[lastRowIndex]) & 0xff))
            else:
                dList[curIndex] = chr((ord(dList[curIndex]) - ord(dList[lastRowIndex]) & 0xff))
            
            unpredicted += dList[curIndex]
        
    return unpredicted

def pAV(data, nCols):
    print "PNG AV predictor not implemented"
    return data

def pPaeth(data, nCols):
    print "PNG Paeth predictor not implemented"
    return data

def pOpt(data, nCols):
    print "PNG OPT predictor not implemented"
    return data

PREDICTORS = { 1:pNone, 2:pTIFF, 10:pNone, 11:pSUB, 12:pUP, 13:pAV, 14:pPaeth, 15:pOpt }


###
if __name__ == "__main__":

    #
    parser = argparse.ArgumentParser(description="Simple PDF dumper/writer")
    parser.add_argument('inFile', help='The input file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Debug output')
    parser.add_argument('-d', '--dumpStreams', action='store_true',
                help='Hexdump streams')
    parser.add_argument('-o', '--outfile', required=False, default="out.pdf",
                help='Output file name')
    parser.add_argument('-f', '--unfilter', action='store_true',
                help='Unfilter streams')
    parser.add_argument('-u', '--unpack', action='store_true',
                help='Unpack objects streams (filter/predictor) and rewrite them to new file unpacked')
    parser.add_argument('-l', '--unpackObjects', type=int, action='append',
                help='List of objects to unpack')
    parser.add_argument('-x', '--extractObjects', type=int, action='append',
                help='List of objects to extract')
    args = parser.parse_args()

    if args.verbose:
        dprint = lambda msg: sys.stdout.write("DEBUG:" + str(msg) + "\n")

    #
    pDoc = pdfDoc(args.inFile)
    pDoc.parse()
    
    #
    if args.unpack:
        if not args.unpackObjects:
            print "You want unpacking but gave no objects, use -l"
        else:
            pDoc.unpackStreams(args.unpackObjects)
            pDoc.emitPDF(args.outfile)
    elif args.extractObjects:
        if args.unfilter:
            pDoc.unpackStreams(args.extractObjects)

        pDoc.extractObjects(args.extractObjects)
    else:
        print "*********************************"
        pDoc.display(args.dumpStreams, args.unfilter)
