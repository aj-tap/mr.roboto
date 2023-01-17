# Mr Roboto
Python scripts that skips repetitive malware analysis tasks.

[![asciicast](https://asciinema.org/a/FtpjDaCq0JAvxB6EY4Rj8aGK1.svg)](https://asciinema.org/a/FtpjDaCq0JAvxB6EY4Rj8aGK1)

#### Features:
- [ x ] Extracts bulk zip password-protected samples.
- [ x ] String Extraction ML based (StringSifter).
- [ x ] PE Analysis tool.
- [ x ] Generate report from CAPA.
- [ x ] Queries hash only of the sample to different CTI.
	- [ x ] Virustotal
	- [   ] Alien OTX 
	- [   ] Malware Bazaar
	- [   ] Generate PDF summary report

---
## Usage
Extracts bulk zip samples with standard "infected" password and pull strings, Capa results and VT search query.
```
python3 main.py --unzip -f <samples-files> -o <saved-specimens> -vt <vt-key>
```
---

## Installation
```
# Clone this repository 
git clone https://github.com/aj-tap/mr.roboto
# Create a virtual environment 
python3 -m venv env 
# Activate virtual environment 
source env/bin/activate
# Install libraries 
pip install -r requirements.txt
# See Instruction
python main.py --help
```