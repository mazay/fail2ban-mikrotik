# Fail2ban MikroTik

A set of tiny scripts for permanently banning malicious offenders.

Uses MySQL database for collecting statistics on intruders or unsuccessful login attempts, ban IP after a certain amount of failures (10 by default).

## Getting Started

### Prerequisites

* MySQL server
* Fail2ban
* Python 2.7
* MikroTik router

### Installing

Clone the repository:
```bash
git clone git@github.com:mazay/fail2ban-mikrotik.git
```

Install python requirements:
```bash
pip install -r requirements.txt
```

Prepare the configuration file:
```bash
cp blacklist_db.cfg_example blacklist_db.cfg
```

Create the MySQL schema for storing statistics data:
```sql
CREATE DATABASE fail2ban CHARACTER SET utf8;

USE fail2ban;

CREATE TABLE `ban_history` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ip_address` char(15) NOT NULL DEFAULT '',
  `country_code` varchar(5) DEFAULT NULL,
  `country_name` varchar(30) DEFAULT NULL,
  `count` int(11) NOT NULL,
  `type` varchar(30) DEFAULT NULL,
  `last_attempt` datetime NOT NULL,
  `first_attempt` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

Adjust the configuration file for your environment:
```ini
[general]
# Path to the log file - optional
log_file = blacklist_db.log
# MySQL connection string
mysql_ip = 10.10.10.10
mysql_user = fancy_username
mysql_password = secure_password
mysql_db = fail2ban

# Number of dailed attempts before permanent ban - optional, default = 10
ban_count = 10
```

Edit fail2ban action files _/etc/fail2ban/action.d/iptables-allports.conf_, _/etc/fail2ban/action.d/iptables-multiport.conf_ and _/etc/fail2ban/action.d/iptables-new.conf_.
Original:
```bash
actionban = iptables -I fail2ban-<name> 1 -s <ip> -j <blocktype>
```

Edited:
```bash
actionban = iptables -I fail2ban-<name> 1 -s <ip> -j <blocktype>
            /path/to/the/script/blacklist_db.py --ip <ip> --type <name>
```

Create crontab schedule for generating MikroTik scripts:
```bash
*/15 * * * * /path/to/the/script/generate_mikrotik_script.py -o /path/to/the/output/dir > /dev/null 2>&1
```

Setup web-server to host the generated file, eg. Nginx:
```bash
    location /blacklists.rsc {
        root /path/to/the/output/dir;
    }
```

### Configuring MikroTik router

Create script for downloading the backlist:
```bash
/system script add name="Download_blacklists" source={
/tool fetch url="http://example.com/blacklists.rsc" mode=http;
:log info "Downloaded blacklists.rsc";
}
```

Create scheduler event for executing the script:
```bash
/system scheduler add comment="Download blacklists" interval=1h name="DownloadBlackLists" on-event=Download_blacklists start-date=jan/01/1970 start-time=01:05:00
```

Create script for importing the backlist:
```bash
/system script add name="Update_blacklists" source={
/ip firewall address-list remove [/ip firewall address-list find comment="BLACKLIST"];
/import file-name=blacklists.rsc;
:log info "Removal old blacklists and add new";
}
```

Create scheduler event for executing the import script:
```bash
/system scheduler add comment="Update BlackList" interval=1h name="InstallBlackLists" on-event=Update_blacklists start-date=jan/01/1970 start-time=01:15:00
```

Create firewall rules for dropping connections originated from the blacklisted IPs, the rules should be placed before the allowing rules:
```bash
/ip firewall filter
add action=reject chain=forward comment="SIP: Reject Blacklisted IP addresses" dst-port=5060-5061 in-interface=INTERNET_IFACE protocol=udp src-address-list=ASTERISK_BLC
add action=reject chain=forward comment="SSH: Reject Blacklisted IP addresses" dst-port=22 in-interface=INTERNET_IFACE protocol=tcp src-address-list=SSH_BLC
```

Where _ASTERISK_BLC_ is name of your filter plus _BLC and _INTERNET_IFACE_ is name your external interface.