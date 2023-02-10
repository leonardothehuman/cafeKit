### Description

A utility that decrypts Wii U NUS content to save space on compression, then 
reencrypt the content with 1:1 output from the original nus package

Please, don't blindly trust 100% in this tool yet, please, after encrypting 
a package, decrypt it and verify if the output is 100% equal the input with 
tools like HashCheck Shell Extension or any other tool to check for duplicate
files ...

### Details

This is a fork of https://github.com/VitaSmith/cdecrypt, which is a fork of 
https://code.google.com/p/cdecrypt intended for people that want to save space
when compressing Wii U game backups in nus format, and want to be able to get exactely 
what they had before decryption.

Unlike cdecrypt, this tool don't allow you to see what is inside the package, it simply
decrypts the content to optimise compression by other tools, like zip, rar, 7z, ntfs...
while allowing you to reencrypt it later and get exactely the same content that
you had before it's decryption.

This software has **no** external dependencies such as OpenSSL libraries and whatnot:
A single executable file is all you need. It also do not need to reside in the same
directory as the NUS content.

### Usage

```
cafeKit [-d|-e] <source directory> <destination directory (optional)>
```

If only the source directory is specified, an output directory will be created
in the directory where the NUS files reside.