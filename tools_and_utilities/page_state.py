# TODO: There are multiple cases of nested TOCs or sequential/concatenated TOCs. I'm not doing anything to detect/process these.
# Possible detections:
#   - look at difference between last item(s) of TOC (probably eof_blink or url_2) and the overall length
#   - scan for the TOC "signature" which seems to be '90 00 00 00 06 00 00 00 88 00 00 00' (06 is key? 90 and 88 are lengths?)
#   - a word like '20 00 00 00' often preceeds these additional TOCs (like the 10 or 08 words seem to indicate LF/skip/seek)

class PageState:
    """ PageState object can parse and structure data from ccl_chromium_snss2.NavigationEntry.page_state_raw """
  
    _TOC_offset = 0x1c              # this byte location was reverse-engineered and may not be robust
    _bonus_field_flag_loc = 0x28    # this byte location seems to indicate the presence of field before TOC1 (uploaded file name?)

    def __init__(self, page_state_raw:str):
        self.TOC:dict = {}
        self.TOC_blink = []

        self.blink_form:list[str] = []
        self.bonus_field:bool = False
        self.post_data:list[str] = []

        self.url:str = ''
        self.url_2:str = ''
        self.referrer_url:str = ''
        self.uuid_1:str = None
        self.uuid_2:str = None

        self.raw:str

        self.raw = page_state_raw
        
        enc_length = self.read_32int_LE(0) + 4    # encoded length word does not count itself
        if enc_length != len(self.raw):
            raise AssertionError("Encoded length: {} != actual length: {}".format(enc_length, len(self.raw)))
        
        self._parse_TOC()
        self._parse_urls()
        self._parse_uuids()
        self._parse_TOC_blink()
        self._parse_blink_fields()
        self._parse_post_data()
        
        if self.raw[self._bonus_field_flag_loc] == 0x01:
            self.bonus_field = True


    def read_32int_LE(self, addr) -> int:
        """ Read/return the 32 bit Little Endian value found at self.raw[addr] """
        result = 0
        for i in range(4):
            result += self.raw[addr + i] * 16**(i*2)
        return result
    

    def index_from_offset(self, addr) -> int:
        """ Return the sum of addr and the offset value read from self.raw[addr] (32 bit Little Endian) """
        return addr + self.read_32int_LE(addr)
    

    def read_field(self, addr):
        """
        Determine the field length from the first 4 bytes at addr.
        Return (field, length) where field does not include the first 4 bytes
        """
        length = self.read_32int_LE(addr)
        return (self.raw[ (addr+4):(addr+length) ], length)
    
    
    def seek_field(self, addr):
        seek_next = True
        while seek_next is True:
            val = self.read_32int_LE(addr)
            if val == 0x10 or val == 0x08:
                addr += val
                next
            else:
                return addr
    

    def decode_field(self, addr):
        """
        1. self.seek_field(addr)
        2. determine encoding from length and character count
        3. return decoded string
        """
        addr = self.seek_field(addr)
        field_length = self.read_32int_LE(addr)
        char_count = self.read_32int_LE(addr+4)
        arr = self.raw[(addr+8):(addr+field_length)]

        enc = ''
        if field_length == char_count + 8:
            enc = 'utf_8'
        elif field_length == (char_count * 2) + 8:
            enc = 'utf_16'
        elif char_count == 0x01:
            # TODO: this is hacky but I found this case and just wanted to get past it without figuring out what's going on.
            # In the problematic case: the first 3 32 bit words were 38, 01, 30. So 30 would be the byte length 38 less the 8 bytes of first two words...
            return arr      
        else:
            raise EncodingWarning
        
        return arr.decode(encoding=enc)
        
        
    def get_bonus_field(self):
        return self.decode_field(self._bonus_field_flag_loc + 4)
    

    def get_TOC_hex(self):
        rtn = []
        for e in self.TOC:
            rtn.append(hex(e))
        return rtn
    
    
    def get_TOC_blink_hex(self):
        rtn = []
        for e in self.TOC_blink:
            rtn.append(hex(e))
        return rtn
    
    
    def _parse_TOC(self):
        addr = self.index_from_offset(self._TOC_offset)

        try:
            assert self.read_32int_LE(addr) == 0x90     # length of TOC
            assert self.read_32int_LE(addr+4) == 0x06   # ?
            assert self.read_32int_LE(addr+8) == 0x88   # offset to end of TOC/start of url
        except:
            raise    # no-op: just a good debugging break point location

        # the 'x' values are reverse-engineered, hard-coded offsets
        x = 0x08; self.TOC['url'] = self.index_from_offset(addr+x)
        
        x = 0x10
        if self.read_32int_LE(addr+x) > 0:
            self.TOC['referrer_url'] = self.index_from_offset(addr+x)
        else:
            self.TOC['referrer_url'] = None
        
        x = 0x18; self.TOC['eof_urls'] = self.index_from_offset(addr+x)
        
        x = 0x20
        if self.read_32int_LE(addr+x) > 0:
            self.TOC['weird_ascii'] = self.index_from_offset(addr+x)
        else:
            self.TOC['weird_ascii'] = None
        
        x = 0x28; self.TOC['sof_blink'] = self.index_from_offset(addr+x)
        x = 0x38; self.TOC['toc_after_blink'] = self.index_from_offset(addr+x)
        x = 0x50; self.TOC['sof_post'] = self.index_from_offset(addr+x)     # value here always seems to always be 20 00 00 00 - skip by 0x20 seems to work, or a mini-TOC?
        x = 0x58; self.TOC['eof_post'] = self.index_from_offset(addr+x)

        x = 0x60
        if self.read_32int_LE(addr+x) > 0:
            self.TOC['url_2'] = self.index_from_offset(addr+x)
        else:
            self.TOC['url_2'] = None
        
        x = 0x68
        if self.read_32int_LE(addr+x) > 0:
            self.TOC['uuid_1'] = self.index_from_offset(addr+x)
        else:
            self.TOC['uuid_1'] = None

        x = 0x70
        if self.read_32int_LE(addr+x) > 0:
            self.TOC['uuid_2'] = self.index_from_offset(addr+x)
        else:
            self.TOC['uuid_2'] = None

        return
    

    def _parse_TOC_blink(self):
        addr = self.TOC['sof_blink']
        len = self.read_32int_LE(addr)
        num_fields = self.read_32int_LE(addr + 4)
        assert len >= (num_fields * 8) + 8      # 8 = 4 bytes for len + 4 bytes for num_fields
        
        addr += 8   # should move us to first/zeroth field (4 bytes each: len, num_fields)
        for i in range(num_fields):
            field_addr = addr + (8 * i)
            self.TOC_blink.insert(i, self.index_from_offset(field_addr))


    def _parse_blink_fields(self):
        """
        The blink TOC may point to an empty field which contains 0x10 and 0x08 values.
        The seek_field() function would "overscan" based on these values and cue the next field.
        We'll pre-seek our addresses so that decode_field() doesn't trigger this case.
        """
        seeked = []
        for i, addr in enumerate(self.TOC_blink):
            seek_addr = self.seek_field(addr)
            if i+1 > len(self.TOC_blink) - 1:
                seeked.insert(i, seek_addr)     # just accept the last field without checking for this over-scan
            elif seek_addr >= self.TOC_blink[i+1]:
                seeked.insert(i, None)          # 'None' will be the checked flag
            else:
                seeked.insert(i, seek_addr)

        for addr in seeked:
            if addr is None:
                self.blink_form.append('')
            else:
                self.blink_form.append(self.decode_field(addr))
    
    
    def _parse_post_data(self):
        """
        reverse-engineered hackery...
        This region seems to use the current "cursor" position 32int data to be a pointer to a 32int value which is the "offset" to the start of the next field
        If true, it's simply a pointer to a pointer to the data which seems dumb but is working.
        Exception: when the first pointer is 0x10, then it precludes the 2nd offset/pointer
        """
        addr = self.TOC['sof_post']

        # Check for empty field: If addr + first pointer is >= TOC['eof_post']
        # (I've always observed 1st pointer to be 0x20 but won't depend on it)
        if addr + self.read_32int_LE(addr) >= self.TOC['eof_post']:
            return
        
        while addr < self.TOC['eof_post']:
            # 1st pointer
            pointer = self.read_32int_LE(addr)
            addr += pointer

            if pointer != 0x10:
                # 2nd pointer/offset value
                addr = self.index_from_offset(addr)

            try:
                self.post_data.append(self.decode_field(addr))
            except:
                raise
            #print(self.decode_field(addr))

            # move addr to end of decoded field
            addr += self.read_32int_LE(addr)
            # then to next 32bit boundary (byte 0x04 or 0x0c of 16 byte "word") if necessary - there are more elegant ways, but this is more readable
            modulo = addr % 16
            if modulo < 4:
                addr += 4 - modulo
            elif 4 < modulo < 12:
                addr += 12 - modulo
            elif 12 < modulo:
                addr += 20 - modulo
    

    def _parse_urls(self):
        self.url = self.decode_field(self.TOC['url'])
        
        if self.TOC['url_2'] is not None:
            self.url_2 = self.decode_field(self.TOC['url_2'])

        if self.TOC['referrer_url'] is not None:
            self.referrer_url = self.decode_field(self.TOC['referrer_url'])

    
    def _parse_uuids(self):
        if self.TOC['uuid_1'] is not None:
            self.uuid_1 = self.decode_field(self.TOC['uuid_1'])
        
        if self.TOC['uuid_2'] is not None:
            self.uuid_2 = self.decode_field(self.TOC['uuid_2'])
