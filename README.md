# Install Unbound

https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/installation.html




## Preparing
Installing Python/Python3
```
apt-get install python
apt-get install python3
apt-get install python-dev
apt-get install python3-dev
```
Install requirement packages
```
sudo apt install -y build-essential
sudo apt install -y libssl-dev
sudo apt install -y libexpat1-dev
sudo apt-get install -y bison
sudo apt-get install -y flex
apt install libevent-dev
apt install swig
```
Creating a Virtual Environment for Python
Install Virtualenv
```
apt-get install python-virtualenv
apt-get install python3-virtualenv
apt get install virtualenv
```
Create a Virtual Environment & Install Python 3
```
cd /home/ubuntu
virtualenv -p /usr/bin/python3 unbound-dev
```
Activate The Virtual Environment
```
cd /home/ubuntu/unbound-dev/bin
source activate
```
## Downloading & Installing Unbound
```
wget https://nlnetlabs.nl/downloads/unbound/unbound-latest.tar.gz
tar xzf unbound-latest.tar.gz
cd unbound-1.17
```
Installing
```
./configure --with-pyunbound --with-pythonmodule --with-libevent
make
make install
```
Check Unbound Version
```
Version 1.17.1

Configure line: --with-pyunbound --with-pythonmodule --with-libevent
Linked libs: libevent 2.1.8-stable (it uses epoll), OpenSSL 1.1.1  11 Sep 2018
Linked modules: dns64 python respip validator iterator

BSD licensed, see LICENSE in source package for details.
Report bugs to unbound-bugs@nlnetlabs.nl or https://github.com/NLnetLabs/unbound/issues

```
Deactivate the Virtualenv
```
deactivate
```
Create user ```unbound```
```
useradd -s /sbin/nologin -d /usr/sbin/unbound -c "unbound" unbound
```



