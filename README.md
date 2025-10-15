# To do
- Explain that cpp code needs to be compiled and give instructions.
- Explain how to run server side locally, and what needs to be selected for these tests.

# TLS connection coding challenge

This is a coding challenge that requires the client to connect to a server,
complete a POW challenge in under 2 hours, and reply to multiple queries.

**Table of Contents**

- [Installation](#installation)
- [Execution / Usage](#execution--usage)
- [Technologies](#technologies)
- [Features](#features)
- [Contributing](#contributing)
- [Contributors](#contributors)
- [Author](#author)
- [Change log](#change-log)
- [License](#license)

## Installation
## Creating client and server side certificates
Follow these steps to create the proper certificates for local testing.  These certificates should be placed in the
"certificates" folder.  The steps are for typing in a Linux terminal. 
### Client side
#### Create a certificate authority (CA)
```sh
$ openssl genrsa -out ca_key.pem 2048
```
```sh
$ openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"`
```
This should create "ca_cert.pem" and "ca_key.pem".

#### Create a client key and certificate signing request (CSR)
```sh
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
```
```sh
$ openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"
```
This should create "client.csr" and "ec_private_key.pem".

#### Sign the client key with the CA
```sh
$ openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365
-sha256
```
This creates "ca_cert.srl" and "client_cert.pem".

### Server side
#### Prepare the server certificates
```sh
$ openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365
```


This creates "server-cert.pem" and "server-key.pem".  You will need to answer a few questions and input a password.  
This password will be used every time you launch the server and use the certificate. 

# Compiling C++ code for finding checksum
The C++ code "pow_benchmark.cpp" is used to find a checksum with enough leading zeroes for specified difficulty.  C++
is used rather than Python due to its speed.

In a Linux terminal, enter:
```sh
$ mkdir ../build
```
```sh
$ g++ -O3 -std=c++17 pow_benchmark.cpp -o ../build/pow_benchmark -lssl -lcrypto -pthread
```




## Execution / Usage

To run < project's name >, fire up a terminal window and run the following command:

```sh
$ <project>
```

Here are a few examples of using the < project's name > library in your code:

```python
from project import Project

...
```

For more examples, please refer to the project's [Wiki](wiki) or [documentation page](docs).

## Technologies

< Project's name > uses the following technologies and tools:

- [Python](https://www.python.org/): ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
- [SQLite](https://sqlite.org/): ![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
- ...

## Features

< Project's name > currently has the following set of features:

- Support for...
- ...

## Contributing

To contribute to the development of < project's name >, follow the steps below:

1. Fork < project's name > from <https://github.com/yourusername/yourproject/fork>
2. Create your feature branch (`git checkout -b feature-new`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add some new feature'`)
5. Push to the branch (`git push origin feature-new`)
6. Create a new pull request

## Contributors

Here's the list of people who have contributed to < project's name >:

- John Doe – [@JohnDoeTwitter](https://twitter.com/< username >) – john@example.com
- Jane Doe – [@JaneDoeTwitter](https://twitter.com/< username >) – jane@example.com

The < project's name > development team really appreciates and thanks the time and effort that all these fellows have put into the project's growth and improvement.

## Author

< Author's name > – [@AuthorTwitter](https://twitter.com/< username >) – author@example.com

## Change log

- 0.0.2
    - Polish the user interface
- 0.0.1
    - First working version
- ...

## License

< project's name > is distributed under the < license > license. See [`LICENSE`](LICENSE.md) for more details.



# Introduction

# Set-up

# How to contribute

# Documentation

# Support

# License

