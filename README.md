# Mr Roboto
Python scripts that skips all repetitive malware analysis tasks.

![](https://github.com/aj-tap/mr.roboto/blob/main/demo-roboto.GIF)

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
```
python3 main.py -e -f <samples-files> -o <saved-specimens> -vt <vt-key>
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
