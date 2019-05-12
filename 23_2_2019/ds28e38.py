

# The DS28E38 is an ECDSA public-key-based secure authenticator.
import time
import machine
import binascii
import os
import json
import onewire

cmd_start = 0x66
cmd_signMessage_len = 34
cmd_read_page = 0xa5
cmd_readPage_len = 2
cmd_read_mem = 0x44
cmd_parameter = 0b00000000

class DS28E38:  
    def __init__(self, onewire):
        self.counter = 0
        dat = machine.Pin(14)
        self.ow = onewire.OneWire(dat)
        self.ow.pin.init(self.ow.pin.OPEN_DRAIN, None)
        self.crc16 = bytearray(2)
        self.roms = []
    
    def onewire_crc16(self,input,crc=0):
        oddparity = [False, True, True, False, True, False, False, True, True, False, False, True, False, True, True, False]
        for cdata in input:
            cdata = (cdata ^ crc) & 0xff
            crc = crc >> 8
            if (oddparity[cdata & 0x0F] == oddparity[cdata >> 4]):
                crc = crc ^ 0xC001  
            cdata = cdata << 6
            crc = crc ^ cdata
            cdata = cdata << 1
            crc = crc ^ cdata
        return crc

  
 # Read status	
    def read_status(self):
        print('---Read status----')
        self.ow.reset()
        self.ow.writebyte(self.ow.SKIP_ROM)
        self.ow.write(b'\x66\x02')
        self.ow.write(b'\xaa\x00')
        self.ow.readinto(self.crc16)
        print('crc16:', binascii.hexlify(self.crc16))
        self.ow.write(b'\xaa') #release byte
        time.sleep_ms(120)	
	
    def read_man_rom_Id(self):
        print("read the rom and the man ids")
        print('dummy:',self.ow.readbyte()) # dummy
        print('length:',self.ow.readbyte()) # length
        print('result:',self.ow.readbyte()) # result
        rx_read_protection_values = bytearray(12)
        self.ow.readinto(rx_read_protection_values)
        for page_num in range(7):
            print("PAGE %i:" % page_num, "{:08b}".format(rx_read_protection_values[page_num]))
            #print("MANID:", binascii.hexlify(rx_read_protection_values[7:9]),"DEVICE_VERSION", binascii.hexlify(rx_read_protection_values[9:11]))#   
        self.crc16 = bytearray(2)
        self.ow.readinto(self.crc16)
        self.roms = self.ow.scan()
        device_data = {}
        #try:
          #print('ROM:', binascii.hexlify(roms[0]))
        self.ow.select_rom(self.roms[0])
        print("check data integrity server")
        #print(onewire_crc16(rx_read_protection_values[7:9]))  
        data = {}
        data['manId'] = binascii.hexlify(rx_read_protection_values[7:9])
        data['romId'] = binascii.hexlify(self.roms[0])
        device_data = json.dumps(data)
        """except Exception as exp:
          #if there is some exceptions, try to recall the function again till we reach limited number of times(3). otherwise throw the exeption
          if (exp and self.counter < 3):
               ds = DS28E38(onewire)
               ds.read_man_rom_Id()
               self.counter+=1
          else:
            raise Exception(exp)"""           
        return device_data
    
    def sign_message(self,challenge):
        print("start siging the message") 
        signature = {}
        self.ow.writebyte(cmd_start)
        self.ow.writebyte(cmd_signMessage_len)
        self.ow.writebyte(cmd_read_page)
        self.ow.writebyte(cmd_parameter)
        self.ow.write(challenge)
        self.ow.readinto(self.crc16)
        print('CRC-16:', binascii.hexlify(self.crc16))
        signature['crc-16'] = binascii.hexlify(self.crc16)
        self.ow.write(b'\xaa') #release byte
        time.sleep_ms(410)
        print("rx_dummy:", self.ow.readbyte())
        print("rx_result_length", self.ow.readbyte())
        print("rx_result_byte", hex(self.ow.readbyte()))
        rx_result = bytearray(64)
        self.ow.readinto(rx_result)
        """print("result:", binascii.hexlify(rx_result))
        print("R:", binascii.hexlify(rx_result[32:64]))
        print("S:", binascii.hexlify(rx_result[0:32]))"""
        self.ow.readinto(self.crc16)
        print('CRC-16:', binascii.hexlify(self.crc16))
        signature['r'] = binascii.hexlify(rx_result[32:64])
        signature['s'] = binascii.hexlify(rx_result[0:32])
        signature_data = json.dumps(signature)
        return signature_data
  
  
    def read_page(self,page_num):
        print("start rading the page")
        #self.roms = self.ow.scan()
        try:
          #print('ROM:', binascii.hexlify(roms[0]))

          self.ow.select_rom(self.roms[0])
        except IndexError:
          raise Exception('ROM not available2')
        self.ow.writebyte(cmd_start)
        self.ow.writebyte(cmd_readPage_len)
        self.ow.writebyte(cmd_read_mem)
        self.ow.writebyte(page_num)
        self.crc16 = bytearray(2)
        self.ow.readinto(self.crc16)
        print('CRC-16:', binascii.hexlify(self.crc16))
        self.ow.write(b'\xaa') #release byte
        time.sleep_ms(410)
        print("rx_dummy:", self.ow.readbyte())
        print("rx_result_length", self.ow.readbyte())
        print("rx_result_byte", hex(self.ow.readbyte()))
        rx_result = bytearray(32)
        self.ow.readinto(rx_result)
        self.ow.readinto(self.crc16)
        print('CRC-16:', binascii.hexlify(self.crc16))
        return rx_result
  

















































