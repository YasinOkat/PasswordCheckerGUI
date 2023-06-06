# Password Checker

Password Checker is a simple desktop application built using PyQt5 that allows you to check the strength and security of your passwords. It leverages the Have I Been Pwned API to check if a password has been previously exposed in data breaches. The application takes the user’s input password and converts it into a
hashed value using the SHA-1 algorithm. It then sends this hashed value to
an API to check the password’s security risk. If the password has been
compromised before, the application informs the user about the number of
times the password has been compromised and advises them to change it.
Otherwise, the password is considered secure.

## Features

- Check the strength and security of your passwords
- Determine if a password has been exposed in data breaches
- User-friendly interface with a minimalistic design
- Dark theme for a sleek and modern look

## Prerequisites

- Python 3.6 or above
- PyQt5 library
- Requests library

## Screenshots

![Screenshot](/screenshots/password_checker.png)
