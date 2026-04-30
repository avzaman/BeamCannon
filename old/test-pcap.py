import pcapy
cap = pcapy.open_live('wlan0',65535,1,50)
header, data = cap.next()
print('Got packet, len:',len(data))
