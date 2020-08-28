# Privify

Android app for encrypting sensitive files directly on the SD card (external storage) with a
user-chosen passphrase. No data is sent over the internet. Technically, file data is encrypted
using AES with a 256 bit key derived using PBKDF2, all using standard Android libraries.
