

try:
  import usocket as socket
except:
  import socket

import network

import gc
gc.collect()

#SSID="DESKTOP12345"                                    #set the wifi ID 
#PASSWORD="00K4r731"

SSID="SouSou's"                                         #set the wifi ID 
PASSWORD="wb4e9j6r"

station = network.WLAN(network.STA_IF)

station.active(True)
station.connect(SSID, PASSWORD)

while station.isconnected() == False:
  pass

print('Connection successful')

print(station.ifconfig())









