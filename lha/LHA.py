from filetypes.base import *
import malcat
import io


class FileHeader(Struct):                                                                                                                                                                      
      def parse(self):
          yield Bytes(1, name="header size", category=Type.HEADER)                                                                                                                               
          yield Bytes(1, name="header checksum", category=Type.HEADER)                                                                                                                           
          yield Bytes(5, name="method id", category=Type.HEADER)                                                                                                                                 
          yield UInt32(name="compressed file size")                                                                                                                                              
          yield UInt32(name="uncompressed file size")
          yield Bytes(4, name="original file date/time", category=Type.HEADER)
          yield Bytes(1, name="file attribute", category=Type.HEADER)
          yield Bytes(1, name="level identifier", category=Type.HEADER)
          name_len = yield UInt8(name="length of filename")
          yield Bytes(name_len, name="path and filename", category=Type.HEADER)
          yield Bytes(2, name="uncompressed crc", category=Type.HEADER)


class LHAAnalyzer(FileTypeAnalyzer):
     category = malcat.FileType.ARCHIVE
     name = "LHA" 
     regexp = r".{2}-lh[d0567]-"

     def __init__(self):
          FileTypeAnalyzer.__init__(self)
          self.filesystem = {}
          self.size = 0

     def open(self, vfile, password=None):
           import io
           from lhafile import LhaFile
           buf = io.BytesIO(self.read(0, self.size))
           lha = LhaFile(buf)
           return lha.read(vfile.path)
      
     def parse(self, hint):
          while self.remaining() > 1:
               if self.read(self.tell(), 1) == b"\x00":
                    yield Bytes(1, name="end of archive", category=Type.HEADER)
                    break
               start = self.tell()
               hdr = yield FileHeader(category=Type.HEADER)
               fn = hdr["path and filename"].decode("latin-1") if hdr["length of filename"] else ""
               compressed_size = hdr["compressed file size"]
               uncompressed_size = hdr["uncompressed file size"]
               yield Bytes(compressed_size, name="compressed data", category=Type.DATA)
          if fn:
               self.filesystem[fn] = (hdr, compressed_size)
               self.add_file(fn, uncompressed_size, "open")
               self.add_section(fn, start, self.tell() - start)
          self.confirm()
          self.size = self.tell()
      

		