# Characterize Service

This Assemblyline service extract information about the file:

* It partitions the file and calculates visual entropy for each partition.
* It runs the hachoir-metadata and exiftool commands to extract metadata information about the file.
* If the file is a Windows Shortcut, this service runs a forked version of the
[LnkParse3](https://github.com/gdesmar/LnkParse3) tool to pull out metadata information.
* If the file is a Web Shortcut, this service will parse the configuration accordingly.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation
