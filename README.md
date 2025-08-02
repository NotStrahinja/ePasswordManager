# ePasswordManager

## What is it?
It is a free, open-source password manager written in Rust, aimed at Windows.

## How does it work?
It uses the DPAPI on Windows to securely store the password database along with the key.

## Is it secure?
Yes. Though there **is** room for improvement. Will continue working on it.

> [!WARNING]
> It is less secure if you don't have a password/PIN on your Windows device. It is recommended to set one if no password/PIN is present.

## Features
1. Encrypted database of passwords with DPAPI (will implement AES soon)
2. Prompting for password/PIN for *extra security*
3. **Password generation**
4. **Advanced options** for the password generation

### Screenshots
*to add*

> [!NOTE]
> This was tested on a Windows 11 25H2 system. Some features may not work on older systems such as Windows 8.

*Linux support coming soon...*
