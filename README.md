# ePasswordManager

## What is it?
It is a free, open-source password manager written in Rust, aimed at Windows.

## How does it work?
It uses the DPAPI on Windows to securely store the password database along with the key.

## Is it secure?
Yes. Unless there are attacks specifically targeted at this program, your passwords are safe.
The password generation feature of this app helps to provide a customizable and reliable option for storing highly random and obfuscated passwords
that are accessible to you with only one click.
Though there **is** room for improvement. Will continue working on it.

> [!WARNING]
> It is less secure if you don't have a password/PIN on your Windows device. It is recommended to set one if no password/PIN is present.

## Features
- [x] Encrypted database of passwords with DPAPI (will implement AES soon)
- [x] Prompting for password/PIN for *extra security*
- [x] **Password generation**
- [x] **Advanced options** for the password generation
- [ ] AES encryption of the database
- [ ] Zeroing out memory of decrypted passwords to prevent RAM dumps
- [ ] Clearing clipboard 30 seconds after copying a password to prevent clipboard hijacking
- [ ] Per-entry decryption
- [ ] Timeout lock
- [ ] Storing the database and the key in `%APPDATA%`

### Screenshots
*to add*

> [!NOTE]
> This was tested on a Windows 11 25H2 system. Some features may not work on older systems such as Windows 8.

*Linux support coming soon...*
