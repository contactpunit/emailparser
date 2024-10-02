# Email Parser using Google OAUTH

This project is about authenticating with gmail using oauth. Once authorization is done it allows facility to read emails from INBOX and store them in mysql db if required.

## Table of Contents

- [Installation](#installation)
- [Pre-requisites for Usage](#Prerequisites)
- [Mysql DB Schema](#mysqlSchema)
- [Usage](#usage)
- [Features](#features)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## Installation

Instructions on how to install and set up the project.

```bash
# Example command
git clone https://github.com/username/repo.git
cd repo
pip install -r requirements.txt
```

## Pre-requisites for Usage

This assumes you have setup:
1. mysql with required configuration
2. have a google account
3. configured Google API client and Google OAuth libraries

## Mysql DB Schema

Below is db schema required for project setup:

![Alt text](images/databases.jpg)

1. **Credentials db**: 

This is the location where gail client id and secrets are stored
