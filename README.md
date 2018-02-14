# Saferide's update-manager Project
update-manager is an open source security configuration project.  
It is a configuration module allowing a (privileged) user to push new security  
policy to the open-sentry via the sysrepo database.  
update-manager have 2 modes of operation:  
1. Local: in this mode the update-manager monitor the security policy configuration  
   file modification (/etc/sentry/config.xsp).
2. Remote: in this mode the update-manager query a server and check if there is a new  
   security policy version. if yes, the update-manager will download the new security policy.
 
 In both cases the new configuration will be pushed to sysrepo DB and this will trigger the open-sentry
 to apply the new configuration.
 
## SW block diagram:
![open_sentry_block_diagram](https://user-images.githubusercontent.com/29350758/36203987-31822170-1192-11e8-95e7-0e2b76cc6887.jpg)  

### Sysrepo:
Open source YANG-based configuration and operational state data store for Unix/Linux applications.  
Allow other application to register callbacks on specific data models that will be invoked upon changes.  
In the OpenSentry solution, sysrepo is used as the security policy rules database.  
https://github.com/sysrepo/sysrepo/  

### OpenSentry:
Security management tool that allow:  
  1. To control various specific security tools (IPTables, SMACK, CANFilter).  
  2. Monitor various security aspects (IP and CAN traffic, processes activities, file access, etc).  
The open_sentry daemon interact with the sysrepo daemon to retrieve the current security  
policy and be notified when this database is changed.  
https://github.com/saferide-tech/open-sentry

### UpdateManager:
This daemon responsible to update the security rules database with the relevant modifications.

## Prerequisites:
1. sysrepo: https://github.com/sysrepo/sysrepo/
2. curl: https://curl.haxx.se/

## Compiling:
```
\# git clone https://github.com/saferide-tech/update-manager.git  
\# cd update-manager  
\# make (can add DEBUG=1)  
```

## Installing:
```
1. copy the update-manager daemon (build/bin/update_manager) to /usr/bin (or any other directory on your PATH).
```

## Running:
```
1. create the configuration file (/etc/sentry/config.xsp).
2. run the daemon:
\# sudo update_manager [-l (local mode), -s server_address (remote mode)]
```

## NOTES:
1. In remote mode, the update_manager will monitor the log file produced by open_sentry  
   and upload the new events to the server.

## Security policy configuration file:
I both modes, remote or local, a configuration file is used.  
This file holds the security rules and their actions we would like to apply.

  To enable the sentry engine:  
  /saferide:control/engine = STATE(start/stop)  

  example:  
```
  /saferide:control/engine = start  
```
  
  Next, we need to declare a set of actions that later will be used by the various rules.
  action struct:
  /saferide:config/sr_actions/list_actions[name='NAME']  
  /saferide:config/sr_actions/list_actions[name='NAME']/action = action (drop/allow)  
  /saferide:config/sr_actions/list_actions[name='NAME']/log/log_facility = facility(syslog/file/none).  
  /saferide:config/sr_actions/list_actions[name='NAME']/log/log_severity = severity (none|critical|error|warning|info|debug)  
  /saferide:config/sr_actions/list_actions[name='NAME']/black-list = false (not used)  
  /saferide:config/sr_actions/list_actions[name='NAME']/terminate = false (not used)  
  NOTE: facility syslog acts the same as file at the moment.

  examples:
```
  /saferide:config/sr_actions/list_actions[name='allow']  
  /saferide:config/sr_actions/list_actions[name='allow']/log/log_facility = none  
  /saferide:config/sr_actions/list_actions[name='allow']/log/log_severity = none  
  /saferide:config/sr_actions/list_actions[name='allow']/black-list = false  
  /saferide:config/sr_actions/list_actions[name='allow']/terminate = false  

  /saferide:config/sr_actions/list_actions[name='log']  
  /saferide:config/sr_actions/list_actions[name='log']/action = allow  
  /saferide:config/sr_actions/list_actions[name='log']/log/log_facility = syslog  
  /saferide:config/sr_actions/list_actions[name='log']/log/log_severity = debug  
  /saferide:config/sr_actions/list_actions[name='log']/black-list = false  
  /saferide:config/sr_actions/list_actions[name='log']/terminate = false  

  /saferide:config/sr_actions/list_actions[name='log_warn']  
  /saferide:config/sr_actions/list_actions[name='log_warn']/action = allow  
  /saferide:config/sr_actions/list_actions[name='log_warn']/log/log_facility = syslog  
  /saferide:config/sr_actions/list_actions[name='log_warn']/log/log_severity = warning  
  /saferide:config/sr_actions/list_actions[name='log_warn']/black-list = false  
  /saferide:config/sr_actions/list_actions[name='log_warn']/terminate = false  

  /saferide:config/sr_actions/list_actions[name='drop_log']  
  /saferide:config/sr_actions/list_actions[name='drop_log']/action = drop  
  /saferide:config/sr_actions/list_actions[name='drop_log']/log/log_facility = syslog  
  /saferide:config/sr_actions/list_actions[name='drop_log']/log/log_severity = error  
  /saferide:config/sr_actions/list_actions[name='drop_log']/black-list = false  
  /saferide:config/sr_actions/list_actions[name='drop_log']/terminate = false  
```

  At the moment we can apply security rules on 2 interfaces: IP & CAN.  
  IP rule struct:  
  /saferide:config/net/ip/rule[num='RULE_NUM']  
  /saferide:config/net/ip/rule[num='RULE_NUM']/action = action_name (should be one of the action names above)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/srcaddr = ip source address  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/srcnetmask = ip source netmask  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/dstaddr = ip dest address  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/dstnetmask = ip dest netmask  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/proto = protocol (0-255)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/srcport = source port number (only valid if proto=6/17)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/dstport = dest port number (only valid if proto=6/17)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/user = (not used)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/program = (not used)  
  /saferide:config/net/ip/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/max_rate = 0 (rate-limit, bytes per sec)  

  IP rules examples:
```
  /saferide:config/net/ip/rule[num='1']  
  /saferide:config/net/ip/rule[num='1']/action = drop  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/srcaddr = 2.2.2.2  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/srcnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/dstaddr = 4.4.4.4  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/dstnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/proto = 0  
  /saferide:config/net/ip/rule[num='1']/tuple[id='1']/max_rate = 0  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/srcaddr = 1.1.1.1  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/srcnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/dstaddr = 3.3.3.3  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/dstnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/proto = 0  
  /saferide:config/net/ip/rule[num='1']/tuple[id='2']/max_rate = 0  
```
  to set a rule only to out direction:  
```
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/srcaddr = 127.0.0.1  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/srcnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/dstaddr = 5.5.5.5  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/dstnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/proto = 0  
  /saferide:config/net/ip/rule[num='1']/tuple[id='3']/max_rate = 0  
```
  to set a rule only to in direction:  
```
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/srcaddr = 6.6.6.6  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/srcnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/dstaddr = 127.0.0.1  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/dstnetmask = 255.255.255.255  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/proto = 0  
  /saferide:config/net/ip/rule[num='1']/tuple[id='4']/max_rate = 0  
```
  CAN rule struct:  
  /saferide:config/net/can/rule[num='RULE_NUM']  
  /saferide:config/net/can/rule[num='RULE_NUM']/action = action_name (should be one of the action names above)  
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']  
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/msg_id = MSG_ID (any|hex 11|29 bits)  
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/direction = DIR (out, in, both)
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/user = (not used)  
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/program = (not used)  
  /saferide:config/net/can/rule[num='RULE_NUM']/tuple[id='TUPLE_ID']/max_rate = 0 (interval between 2 messgaes with the same msg_id)  

  CAN rules examples:
  set a rate limit on specific message  
```
  /saferide:config/net/can/rule[num='4']  
  /saferide:config/net/can/rule[num='4']/action = drop  
  /saferide:config/net/can/rule[num='4']/tuple[id='1']  
  /saferide:config/net/can/rule[num='4']/tuple[id='1']/msg_id = 5A0  
  /saferide:config/net/can/rule[num='4']/tuple[id='1']/direction = out  
  /saferide:config/net/can/rule[num='4']/tuple[id='1']/max_rate = 50  
```
  log all can messages in both directions  
```
  /saferide:config/net/can/rule[num='2']  
  /saferide:config/net/can/rule[num='2']/action = log  
  /saferide:config/net/can/rule[num='2']/tuple[id='1']  
  /saferide:config/net/can/rule[num='2']/tuple[id='1']/msg_id = any  
  /saferide:config/net/can/rule[num='2']/tuple[id='1']/direction = both  
  /saferide:config/net/can/rule[num='2']/tuple[id='1']/max_rate = 0  
```

for more information on the fields please read https://github.com/saferide-tech/open-sentry/blob/master/yang/saferide.yang  

