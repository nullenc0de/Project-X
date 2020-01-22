#!/bin/bash -i

echo -e "
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|k|e|n|t|s|l|a|v|e|s|I|n|s|t|a|l|l|e|r|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
AUTHOR: KENT BAYRON @Kntx"
echo -e "INSTALLER FOR RECON-TOOL"
echo "USAGE:./install.sh"

#======================#
# Install Dependencies #
#======================#
apt install python3-pip
apt install make
apt install unzip

#============#
# Go Install #
#============#
mkdir ~/Research/
mkdir ~/Research/Tools/
mkdir ~/Research/Targets/
mkdir ~/Research/Tools/GoTools/

cd ~/Research/Tools/
wget https://dl.google.com/go/go1.13.6.linux-amd64.tar.gz 
tar -C /usr/local -xzf go1.13.6.linux-amd64.tar.gz

#===========#
# Go Config #
#===========#
echo 'export GOPATH=$HOME/Research/Tools/GoTools' >> ~/.bashrc 
echo 'export PATH=${PATH}:${GOPATH}/bin' >> ~/.bashrc 
echo 'export PATH=$PATH:/usr/local/go/bin'  >> ~/.bashrc
source ~/.bashrc

#==========#
# Go Tools #
#==========#

# AMASS 
export GO111MODULE=on
go get -v -u github.com/OWASP/Amass/v3/...

# ASSETFINDER
go get -u github.com/tomnomnom/assetfinder

# FINDOMAIN 
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
mv findomain-linux findomain
sudo mv findomain /usr/bin/

# SUBFINDER
go get -u -v github.com/projectdiscovery/subfinder/cmd/subfinder

# DNSGEN
pip3 install dnsgen

# MASSDNS
https://github.com/blechschmidt/massdns.git
mv massdns Massdns
cd Massdns
make

# FILTER-RESOLVED
go get github.com/tomnomnom/hacks/filter-resolved

# HTTPROBE
go get -u github.com/tomnomnom/httprobe

# HAKRAWLER
go get github.com/hakluke/hakrawler

# SHODAN
pip install shodan

# SUBJACK
go get github.com/haccer/subjack

# TKO-SUBS
go get github.com/anshumanbh/tko-subs

# WEBANALYZE
go get -u github.com/rverton/webanalyze/...

# AQUATONE
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
rm README.md
rm LICENSE.txt
mv aquatone ~/Research/Tools/GoTools/bin

#WEBSCREENSHOT
pip install webscreenshot

# SMUGGLER
mkdir ~/Research/Tools/Smuggler/
wget https://github.com/gwen001/pentest-tools/blob/master/smuggler.py
mv smuggler.py ~/Research/Tools/Smuggler/

# LINKFINDER
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python setup.py install

# OTXURLS
go get github.com/lc/otxurls

# WAYBACKURLS
go get github.com/tomnomnom/waybackurls

# GITHUB ENDPOINT
mkdir ~/Research/Tools/GitHubTool/
wget https://github.com/gwen001/github-search/blob/master/github-endpoints.py
mv github-endpoints.py ~/Research/Tools/GitHubTool

rm go1.13.6.linux-amd64.tar.gz
rm aquatone_linux_amd64_1.7.0.zip
