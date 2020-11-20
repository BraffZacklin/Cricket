# Cricket
A WiFi Jammer with multiple attack modes
  1. Unarmed - Only sniffs for handshakes & beacon frames to find new APs
  2. Target - Only target specific AP's
  3. Spray - Attack every AP until a WPA2 handshake is acquired, then move on
  4. Jammer - Attack every AP

Options included to ignore certain APs by ESSID or BSSID, using a second WiFi interface (allowing dedicating sending and receiving), to customise channel hopping, and to add a .pcap file to write handshakes to

Note, when using it, it'll be helpful if your receiving interface is in monitor mode (and your sending interface supports packet injection)
So, before using it, run these commands
  sudo ip link set <recvInt> down
  sudo iw dev <recvInt> set type monitor
  sudo ip link set <recvInt> up
It's also recommended that you stop network-manager, either with
  sudo service network-manager stop
or
  sudo airmon-ng check kill
  
Don't do anything I wouldn't recommend you to do with this <3
