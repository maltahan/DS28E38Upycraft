



try:
  import usocket as socket
except:
    import socket
import binascii
import json
import ds28e38
import onewire
import _onewire as _ow
import network
import time
import os
import struct


counter = 0
challenge = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create stream socket
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   #Set the value of the given socket option
s.bind(('', 80))                      #bind ip and port
s.listen(20)
class Main: 
    def connect_to_ds28e38(self):
        while True:                             #Accept a connection,conn is a new socket object           
            conn, addr = s.accept()
            counter = 0
            print("Got a connection from %s" % str(addr))
            request = conn.recv(1024)                           #Receive 1024 byte of data from the socket
            ds = ds28e38.DS28E38(onewire)
            #the crc for the sequence of commands to get the signature 
            data = bytearray(b'\x66\x22\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            crc = ds.onewire_crc16(data)
            packed_crc = struct.pack('H', crc)
            inverted_crc = bytearray((b^0xFF for b in packed_crc))
            print(binascii.hexlify(inverted_crc))
            ds.read_status()
            try:
              man_rom_data = json.loads(ds.read_man_rom_Id())
            except Exception as exp:
              if(exp and counter < 3):
                print("start start")
                print(exp)
                man_rom_data = json.loads(ds.read_man_rom_Id())
                counter+=1
              else:
                print(exp)  
            print(man_rom_data)
            signature_data = json.loads(ds.sign_message(challenge))
            print(signature_data)
            page_data = binascii.hexlify(ds.read_page(0))
            publickey_x = binascii.hexlify(ds.read_page(4))
            publickey_y = binascii.hexlify(ds.read_page(5))
            complete_data = {}
            complete_data['romId'] = man_rom_data['romId']
            complete_data['manId'] = man_rom_data['manId']
            complete_data['publicKey_x'] = publickey_x
            complete_data['publicKey_y'] = publickey_y
            complete_data['r'] = signature_data['r']
            complete_data['s'] = signature_data['s']
            complete_data['crc-16'] = signature_data['crc-16']
            complete_data['page_data'] = page_data
            complete_data['challenge'] = binascii.hexlify(challenge)
            signature_data_json = json.dumps(complete_data)
            res = signature_data_json
            conn.sendall('HTTP/1.1 200 OK\nConnection: close\nServer: FireBeetle\nContent-Type: application/json\nAccess-Control-Allow-Origin:*\nContent-length:{:d}\n\n'.format(len(signature_data_json)))
            conn.sendall(signature_data_json)
            conn.close()                                        #close file 
            print("Connection with %s closed" % str(addr))
            time.sleep(2)
            

try:
  obj = Main() 
  obj.connect_to_ds28e38()
except Exception as exp:
      #if there is some exceptions, try to recall the function again till we reach limited number of times(3). otherwise throw the exeption
     if (exp and counter < 3):
      print("start calling the socket again")
      new_obj = Main()   
      new_obj.connect_to_ds28e38()
      counter+=1
     else:
        print(exp)














































