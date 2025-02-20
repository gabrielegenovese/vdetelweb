# VDETELWEB

### Telnet, SSH and WEB interface for VDE2

Depends on the LWIPv6a library, available as a GPLv2 project from 
`http://savannah.nongnu.org/projects/view-os`

How to install:
```
mkdir build
cmake ..
make
sudo make install
```

How to use:

Create a `vdetelwebrc` file.
the program searches for `/etc/vde/vdetelwebrc` and `~/etc/vde/vdetelwebrc`.
Different path for the rc file can be given by the `-f` option.

```
*********************** Sample vdetelwebrc file **************************
#vdetelweb rc sample
ip4=192.168.0.253/24
defroute4=192.168.0.1
password=e8b32ad31b34a21d9fa638c2ee6cf52d46d5106b
*********************** END Sample vdetelwebrc file **************************
```

The password in the example is "piripicchio".
The hash of the password has been obtained by the following command:
```
$ echo -n piripicchio | sha1sum
```
VDETELWEB creates a telnet and/or web interface to a running VDE switch.
The switch must have been started with the remote mgmt option (-m).
```
% vde_switch -M /tmp/vde.mgmt -daemon
```
Launch the tool:
```
% vdetelweb -t -w -s -f vdetelwebrc /tmp/vde.mgmt
```
Now it is possible to use telnet, ssh or a browser to manage the switch.

(c) 2005 Renzo Davoli - Department of Computer Science. University of Bologna.

(c) 2008 Renzo Davoli, Marco Dalla Via. Editing of commands and sha1 passwd

(c) 2021 Renzo Davoli - Virtualsquare and CSE Department, University of Bologna.
porting to cmake.

(c) 2023 Renzo Davoli, Gabriele Genovese - Virtualsquare and CSE Department, University of Bologna.
lwip to ioth migration, ssh module, https upgrade.
