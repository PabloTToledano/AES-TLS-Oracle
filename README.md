# AES-TLS-Oracle
Oracle based attack for TLS-AES
# Run instructions

You will need to provided your own oracle URIs.

AES Oracle Padding attack

options:
  -h, --help            show this help message and exit
  -m {error,time}, --mode {error,time}
                        oracle mode (default: None)
  -s, --sequential      sequential mode for time oracle (default: False)
  -n NAME, --name NAME  name (default: None)
