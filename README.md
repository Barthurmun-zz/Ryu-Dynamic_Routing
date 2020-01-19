# SDN Ryu-Controller -- Load-Balancing with Dynamic-Routing
SDN Ryu controller  with Load Balancing and dynamic routing

OpenFlow version used: OpenFlow 1.3
Description: Project during which I have created Ryu controller which performs BFS algorithm to find best paths, based on traffic flowing through links optimal path is being choosen from possible paths. The costs are being calculated in the background (action performed by thread) and optimal path is being updated every second based on the gathered stats. Discover of topology is done automatically so we don't have to have specially prepared topology.

Based on: 
  https://ryu.readthedocs.io/en/latest/ryu_app_api.html
  https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch.py
  https://github.com/wildan2711/multipath/blob/master/ryu_multipath.py
