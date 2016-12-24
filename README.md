![CheetoFTP](logo.png "CheetoFTP")

## About
CheetoFTP is a cheese flavoured FTP discovery script written for [ArchiveTeam](http://www.archiveteam.org)'s Operation #CheetoFlee.

## Requirements
You'll need:

* Python 3.4+
* Stefan Schwarzer's amazing [ftputil](http://ftputil.sschwarzer.net/trac/wiki/WikiStart) library.
* Moist toilettes for the neon cheese dust.

## Installation
### Make sure you have the _ftputil_ library
```
pip install ftputil
```
### Clone the repo
```
git clone https://github.com/413mbic/CheetoFTP.git
```
## Usage
```
usage: cheetoftp_cli.py [-h] [--user User] [--passwd Passwd]
                        [--threads Threads] [--max-itemsize Max Itemsize]
                        URL

CheetoFTP - A cheese flavoured FTP file discovery script.

positional arguments:
  URL                   URL to scan

optional arguments:
  -h, --help            show this help message and exit
  --user User           Username to use to login into the FTP URL. Defaults to
                        `anonymous`.
  --passwd Passwd       Password to use to login into the FTP URL. Defaults to
                        `anonymous`.
  --threads Threads     The number of concurrent connections to make to the
                        FTP server while scanning. Defaults to 2.
  --max-itemsize Max Itemsize
                        The number of bytes each item should aspire to be.
                        Defaults to 209715200.
```

## License
CheetoFTP is free and unencumbered software released into the public domain. For full license information, please see the UNLICENSE file.