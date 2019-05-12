

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


    challenge = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create stream socket
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   #Set the value of the given socket option
    s.bind(('', 80))                      #bind ip and port
    s.listen(20)  
    
    def connect_to_ds28e38(): 
      while True:
        conn, addr = s.accept()                             #Accept a connection,conn is a new socket object
        print("Got a connection from %s" % str(addr))
        request = conn.recv(1024)                           #Receive 1024 byte of data from the socket
        ds = ds28e38.DS28E38(onewire)
        print("the crc for the sequence of commands to get the signature is:")
        data = bytearray(b'\x66\x22\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        crc = ds.onewire_crc16(data)
        packed_crc = struct.pack('H', crc)
        inverted_crc = bytearray((b^0xFF for b in packed_crc))
        print(binascii.hexlify(inverted_crc))
        ds.readStatus()
        ManRomdata = json.loads(ds.read_man_rom_Id())
        print(ManRomdata)
        signatureData = json.loads(ds.sign_message(challenge))
        print(signatureData)
        pageData = binascii.hexlify(ds.read_page(0))
        publickey_x = binascii.hexlify(ds.read_page(4))
        publickey_y = binascii.hexlify(ds.read_page(5))
        completeData = {}
        completeData['romId'] = ManRomdata['romId']
        completeData['manId'] = ManRomdata['manId']
        completeData['publicKey_x'] = publickey_x
        completeData['publicKey_y'] = publickey_y
        completeData['r'] = signatureData['r']
        completeData['s'] = signatureData['s']
        completeData['crc-16'] = signatureData['crc-16']
        completeData['page_data'] = pageData
        completeData['challenge'] = binascii.hexlify(challenge)
        signature_data_json = json.dumps(completeData)
        print(signature_data_json)
        conn.sendall('HTTP/1.1 200 OK\nConnection: close\nServer: FireBeetle\nContent-Type: application/json\nAccess-Control-Allow-Origin:*\nContent-length:{:d}\n\n'.format(len(signature_data_json)))
        conn.sendall(signature_data_json)
        conn.close()                                        #close file 
        print("Connection wth %s closed" % str(addr))


  
try: 
  connectToDS28E38()
except Exception as a:
  if (s):
    print('there is a problem with the socket')
    print(a)
    s.close()


    





































