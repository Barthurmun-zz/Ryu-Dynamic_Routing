# SDN Ryu-Controller -- Load-Balancing with Dynamic-Routing
SDN Ryu controller  with Load Balancing and dynamic routing

Project during which I have created Ryu controller which performs BFS algorithm to find best path and calculate all costs. The costs are being calculated in the background every second (action performed by thread) and best path is auto adjusting. Discover of topology is done automatically so we don't have to have specially prepare topology.

Based on: 
  https://ryu.readthedocs.io/en/latest/ryu_app_api.html
  https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch.py
  https://github.com/wildan2711/multipath/blob/master/ryu_multipath.py
