# Install Unbound

https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/installation.html

```
useradd -s /sbin/nologin -d /usr/sbin/unbound -c "unbound" unbound
```
```
./configure --with-libevent --with-pythonmodule PYTHON=3 PYTHON_LDFLAGS="-L/usr/lib/python3.8/config-3.8m-x86_64-linux-gnu -L/usr/lib -lpython3.8m -lcrypt -lpthread -ldl -lutil -lm" PYTHON_CPPFLAGS="-I/usr/include/python3.8m -I/usr/include/python3.8m"

```
