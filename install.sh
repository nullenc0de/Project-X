#!/bin/bash -i

echo -e "
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|k|e|n|t|s|l|a|v|e|s|I|n|s|t|a|l|l|e|r|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
AUTHOR: KENT BAYRON @Kntx"
echo -e "INSTALLER FOR RECON-TOOL"
echo "USAGE:./install.sh"

#============================#
# Install Dependencies [APT] #
#============================#
apt install python3-pip -y
apt install make -y
apt install unzip -y
apt install jq -y
apt install phantomjs -y
apt install libpcap-dev -y

#===========================#
# Install Dependencies [PIP3#
#===========================#
pip3 install colored 

#============#
# Go Install #
#============#
mkdir ~/Research/
mkdir ~/Research/Tools/
mkdir ~/Research/Targets/
mkdir ~/Research/Tools/Others/
mkdir ~/Research/Tools/GoTools/

cd ~/Research/Tools/

#===============================#
# Install Dependencies [APPS]   #
#===============================#

wget https://dl.google.com/go/go1.13.6.linux-amd64.tar.gz 
tar -C /usr/local -xzf go1.13.6.linux-amd64.tar.gz
rm go1.13.6.linux-amd64.tar.gz

wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install ./google-chrome-stable_current_amd64.deb -y
rm google-chrome-stable_current_amd64.deb

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

# OTXURLS
go get -u github.com/lc/otxurls

# WAYBACKURLS
go get -u github.com/tomnomnom/waybackurls

# SUBFINDER
go get -u -v github.com/projectdiscovery/subfinder/cmd/subfinder

# FILTER-RESOLVED
go get -u github.com/tomnomnom/hacks/filter-resolved

# HTTPROBE
go get -u github.com/tomnomnom/httprobe

# HAKRAWLER
go get -u github.com/hakluke/hakrawler

# QSREPLACE
go get -u github.com/tomnomnom/qsreplace

# SUBJACK
go get -u github.com/haccer/subjack
wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json
mv fingerprints.json ~/Research/Tools/Others/

# WEBANALYZE
go get -u github.com/rverton/webanalyze/...

# TKO-SUBS
go get -u github.com/anshumanbh/tko-subs
wget https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv
mv providers-data.csv ~/Research/Tools/Others/

# FINDOMAIN
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
mv findomain-linux findomain
sudo mv findomain /usr/bin/

# DNSGEN
pip3 install dnsgen

# SHODAN
pip3 install shodan

#WEBSCREENSHOT
pip3 install webscreenshot

# AQUATONE
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
rm README.md
rm LICENSE.txt
mv aquatone ~/Research/Tools/GoTools/bin
rm aquatone_linux_amd64_1.7.0.zip

# SMUGGLER
mkdir ~/Research/Tools/Smuggler/
wget https://raw.githubusercontent.com/gwen001/pentest-tools/master/smuggler.py
mv smuggler.py ~/Research/Tools/Smuggler/

# GITHUB ENDPOINT
mkdir ~/Research/Tools/GitHubTool/
wget https://raw.githubusercontent.com/gwen001/github-search/master/github-endpoints.py
mv github-endpoints.py ~/Research/Tools/GitHubTool

# MASSDNS
git clone https://github.com/blechschmidt/massdns.git
mv massdns Massdns
cd Massdns
make
cd -

# LINKFINDER
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder 
python3 setup.py install
cd -

echo 'INSTALLATION IS FINISHED'
