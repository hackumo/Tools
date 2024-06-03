# Decoy Dog analysis toolkit
The toolkit to help analyze Decoy Dog malware. Decoy Dog is multi-functional and multi-platform backdoor based on the open-source project [Pupy RAT](https://github.com/n1nj4sec/pupy). Additional technical information can be found [here](https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/hellhounds-operation-lahat/) and [here](https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/hellhounds-operation-lahat-part-2/).

## Linux
Let's look at how to use the toolkit to decrypt the payload for Linux. Suppose we found the loader. First we need to get the machine identifier that is one of the following files on infected machine:
```
/etc/machine-id
/run/machine-id
/var/lib/dbus/machine-id
/var/db/dbus/machine-id
/usr/local/etc/machine-id
/sys/class/dmi/id/product_uuid
/sys/class/dmi/id/board_serial
/etc/hostid
/proc/self/cgroup
```

Then we use the `loader` command and the found identifier using the `--machine-id` parameter to decrypt the loader configuration using the following command:
```commandline
toolkit.py linux loader --file /home/hackumo/samples/crond --machine-id /home/hackumo/samples/machine-id
```

And we get the following output:
```
[+] Payload path: /usr/bin/aptitude-common
[+] Payload size: 4195780
```

So, we need to get file `/usr/bin/aptitude-common` of size 4195780 bytes and then use the `payload` command to decrypt it:
```commandline
toolkit.py linux payload --file /home/hackumo/samples/aptitude-common --machine-id /home/hackumo/samples/machine-id
```

And we get the following output:
```
[+] Decrypted payload was written to /home/hackumo/samples/aptitude-common.dec
```

Let me note that we can decrypt the payload without finding the loader. We only need to get the identifier of the infected machine.


## Windows
Windows-specific versions don't use the machine identifier, but we need to to specify the name of the loader used on the infected system using the `--name` parameter:
```commandline
toolkit.py windows loader --file /home/hackumo/samples/AccSrvX64__STABLE__2016-11-10.exe --name AccSrvX64__STABLE__2016-11-10.exe
```

Sometimes we can get output like this:
```
[!] Can't lookup dns.msftncsi.com. Try to find historical data through Passive DNS.
[+] DNS commands:
  -act0.microsoft.com
  dns.msftncsi.com
[!] Can't decrypt payload path, try --ip option
```

This means that the toolkit was unable to obtain the IP address of the specified domain. We can find it ourselves, using, for example, Passive DNS services, and then specify the found IP address using the `--ip` parameter:
```commandline
toolkit.py windows loader --file /home/hackumo/samples/AccSrvX64__STABLE__2016-11-10.exe --name AccSrvX64__STABLE__2016-11-10.exe --ip 131.107.255.255
```

And then we get the following output:
```
[+] DNS commands:
  -act0.microsoft.com
  dns.msftncsi.com
[+] Payload path: C:\[REDACTED]\NPipeX64_32.dll
```

Next we use the `payload` command to decrypt the encrypted payload:
```commandline
toolkit.py windows loader --file /home/hackumo/samples/NPipeX64_32.dll --name AccSrvX64__STABLE__2016-11-10.exe --ip 131.107.255.255
```

We still need to use `--name` and `--ip` parameters because the same encryption scheme with the same key generation algorithm used in the payload decryption.

After that we get the following output:
```
[+] Decrypted payload was written to /home/hackumo/samples/NPipeX64_32.dll.dec
```