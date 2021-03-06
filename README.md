saslpolicyd
===========

saslpolicyd is a policy daemon for postfix. The software is written in perl and licensed under the Apache License 2.0.

As a service provider, you have to deal with stolen passwords. Such accounts are often used for abusive actions. Nowadays, botnets are using stolen passwords for sending huge amounts of spam mails over a smarthost. In this case, your mailservers have to relay thousands of spam mails. All mails are received by authenticated SMTP-connections. 

Often, the missuse follows the same pattern: normally a customer relays only a handful of mails during a week. The mails are delivered from a few source ips. In a missuse case, more than 1000 mails are relayed from more then 30 ips in one hour. This is the reason why I wrote this tool. saslpolicyd tracks all sasl logins and reject the relay if a missuse case is detected.


Features
-------------
* Limit total logins per user
* Limit different source ips per user
* Whitelist ip ranges
* Configure special rate limits per user


Installation
-------------
* Download and unpack the software
* Copy the policy daemon to /usr/sbin
* Copy the configuration file to /etc
* Start the service

If you are using Debian or Ubuntu you can build your own dpkg-package by using the content of the debian/ folder.

* Add the policy service to your postfix configuration (/etc/postfix/main.cf):

```
  smtpd_client_restrictions = check_policy_service inet:127.0.0.1:25025,
  ...
```

Configuration file
-----------------
If you need to configure special rate limits per user, you can define them in the configuration file (/etc/saslpolicyd.conf):


```
# Set a rate limit of 1000 mails from 20 differnt IPs for sasl-user "web100"
userlimit: web100 1000 20
```

