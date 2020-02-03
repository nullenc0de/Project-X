#!/bin/bash -i

banner (){
echo -e "
+-+-+-+-+-+-+-+-+-+-+
|k|e|n|t|s|l|a|v|e|s|
+-+-+-+-+-+-+-+-+-+-+
AUTHOR: KENT BAYRON @Kntx"
}

kill (){
        banner
    echo -e "RECONNAISSANCE TOOL FOR BUGBOUNTY"
    echo "USAGE:./recon.sh domain.com"
    exit 1
}

recon (){
banner
github_token=
mkdir ~/Research/Targets/$1
mkdir ~/Research/Targets/$1/Shodan
mkdir ~/Research/Targets/$1/GitHub
mkdir ~/Research/Targets/$1/Screenshots
mkdir ~/Research/Targets/$1/Endpoints
mkdir ~/Research/Targets/$1/Archived
mkdir ~/Research/Targets/$1/SubdomainTakeover
mkdir ~/Research/Targets/$1/JSFiles
mkdir ~/Research/Targets/$1/Smuggle
echo $1 > ~/Research/Targets/$1/$1.root.txt
cat ~/Research/Targets/$1/$1.root.txt  | grep -Po "[\w\s]+(?=\.)" >> ~/Research/Targets/$1/$1.domain.txt
cd ~/Research/Targets/$1
echo -e "\e[31m[STARTING]\e[0m"

## LAUNCH AMASS
echo -e "\nRUNNING \e[31m[AMASS PASSIVE]\e[0m"
amass enum -config /root/config.ini -passive -d $1 -o ~/Research/Targets/$1/$1.amasspassive.txt 
echo "FOUND SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.amasspassive.txt | wc -l)]"
echo "RUNNING AMASS \e[32mFINISH\e[0m"

## LAUNCH ASSETFINDER
echo -e "\nRUNNING \e[31m[ASSETFINDER]\e[0m"
assetfinder -subs-only $1 > ~/Research/Targets/$1/$1.assetfinder.txt
echo "FOUND SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.assetfinder.txt | wc -l)]"
echo "RUNNING ASSETFINDER \e[32mFINISH\e[0m"

## LAUNCH FINDOMAIN
echo -e "\nRUNNING \e[31m[FINDOMAIN]\e[0m"
findomain -t $1 -o
echo "FOUND SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.txt | wc -l)]"
echo "RUNNING FINDOMAIN \e[32mFINISH\e[0m"

## LAUNCH DNSBUFFER
echo -e "\nRUNNING \e[31m[DNSBUFFEROVER]\e[0m"
curl -s https://dns.bufferover.run/dns?q=.$1 | jq -r .FDNS_A[]|cut -d',' -f2 > ~/Research/Targets/$1/$1.dnsbuffer.txt
echo "FOUND SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.dnsbuffer.txt | wc -l)]"
echo "RUNNING DNSBUFFER \e[32mFINISH\e[0m"

## LAUNCH SUBFINDER
echo -e "\nRUNNING \e[31m[SUBFINDER]\e[0m"
subfinder -d $1 -o ~/Research/Targets/$1/$1.subfinder.txt 
echo "FOUND SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.subfinder.txt | wc -l)]"
echo "RUNNING SUBFINDER \e[32mFINISH\e[0m"

## REMOVING DUPLICATES
sort  ~/Research/Targets/$1/$1.amasspassive.txt ~/Research/Targets/$1/$1.subfinder.txt ~/Research/Targets/$1/$1.txt ~/Research/Targets/$1/$1.assetfinder.txt ~/Research/Targets/$1/$1.dnsbuffer.txt | uniq > ~/Research/Targets/$1/$1.alldomains.txt
echo "REMOVING DUPLICATES \e[32mFINISH\e[0m"

## LAUNCH DNSGEN & MASSDNS
echo -e "\nRUNNING \e[31m[MASSDNS & DNSGEN]\e[0m"
cat ~/Research/Targets/$1/$1.alldomains.txt | dnsgen - | ~/Research/Tools/Massdns/bin/massdns -r ~/Research/Tools/Massdns/lists/resolvers.txt -t A -o S -w ~/Research/Targets/$1/$1.massdns.txt
echo "RESOLVED SUBDOMAINS [$(cat ~/Research/Targets/$1/$1.massdns.txt | wc -l)]"
echo "RUNNING DNSGEN & MASSDNS \e[32mFINISH\e[0m"

## REMOVING DUPLICATES
sort ~/Research/Targets/$1/$1.massdns.txt | awk '{print $1}' | sed 's/\.$//' | uniq > ~/Research/Targets/$1/$1.resolved.txt
wildcheck -i ~/Research/Targets/$1/$1.resolved.txt -t 100 -p |grep "non-wildcard" |cut -d ' ' -f3 > ~/Research/Targets/$1/$1.resolved_no_wildcard.txt
mv ~/Research/Targets/$1/$1.resolved_no_wildcard.txt ~/Research/Targets/$1/$1.resolved.txt
sort ~/Research/Targets/$1/$1.resolved.txt ~/Research/Targets/$1/$1.alldomains.txt |  uniq > ~/Research/Targets/$1/$1.all-final.txt

## LAUNCH LIVEHOSTS
echo -e "\nRUNNING \e[31m[LIVEHOSTS]\e[0m"
cat ~/Research/Targets/$1/$1.all-final.txt | filter-resolved -c 100  >  ~/Research/Targets/$1/$1.all-resolved.txt 
cat ~/Research/Targets/$1/$1.all-final.txt | httprobe -c 100 >>  ~/Research/Targets/$1/$1.all-resolved.txt
cat ~/Research/Targets/$1/$1.all-resolved.txt | httprobe -c 100 >> ~/Research/Targets/$1/$1.livehost.txt
sort ~/Research/Targets/$1/$1.livehost.txt | uniq >> ~/Research/Targets/$1/$1.livehosts.txt
rm ~/Research/Targets/$1/$1.livehost.txt
cat ~/Research/Targets/$1/$1.livehosts.txt | sed 's/https\?:\/\///' > ~/Research/Targets/$1/$1.probed.txt
echo "LIVE HOSTS [$(cat ~/Research/Targets/$1/$1.livehosts.txt | wc -l)]"
echo "RUNNING LIVEHOSTS \e[32mFINISH\e[0m"

## LAUNCH HAKCRAWLER
echo -e "\nRUNNING \e[31m[HAKCRAWLER]\e[0m"
for hak in $(cat ~/Research/Targets/$1/$1.livehosts.txt); do
       hakrawler -url $hak -linkfinder >> ~/Research/Targets/$1/$1.Crawler.txt
done
echo "RUNNING HAKCRAWLER \e[32mFINISH\e[0m"

## RUNNING SHODAN
echo -e "\nRUNNING \e[31m[SHODAN HOST]\e[0m"
dig +short -f ~/Research/Targets/$1/$1.probed.txt > ~/Research/Targets/$1/ips.txt
cat ~/Research/Targets/$1/ips.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> ~/Research/Targets/$1/ip.txt
sort ~/Research/Targets/$1/ip.txt | uniq > ~/Research/Targets/$1/$1.ip.txt

iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22 199.83.128.0/21 198.143.32.0/19 149.126.72.0/21 103.28.248.0/22 45.64.64.0/22 185.11.124.0/22 192.230.64.0/18 107.154.0.0/16 45.60.0.0/16 45.223.0.0/16 185.93.228.0/24 185.93.229.0/24 185.93.230.0/24 185.93.231.0/24 192.124.249.0/24 192.161.0.0/24 192.88.134.0/24 192.88.135.0/24 193.19.224.0/24 193.19.225.0/24 66.248.200.0/24 66.248.201.0/24 66.248.202.0/24 66.248.203.0/24 104.101.221.0/24 184.51.125.0/24 184.51.154.0/24 184.51.157.0/24 184.51.33.0/24 2.16.36.0/24 2.16.37.0/24 2.22.226.0/24 2.22.227.0/24 2.22.60.0/24 23.15.12.0/24 23.15.13.0/24 23.209.105.0/24 23.62.225.0/24 23.74.29.0/24 23.79.224.0/24 23.79.225.0/24 23.79.226.0/24 23.79.227.0/24 23.79.229.0/24 23.79.230.0/24 23.79.231.0/24 23.79.232.0/24 23.79.233.0/24 23.79.235.0/24 23.79.237.0/24 23.79.238.0/24 23.79.239.0/24 63.208.195.0/24 72.246.0.0/24 72.246.1.0/24 72.246.116.0/24 72.246.199.0/24 72.246.2.0/24 72.247.150.0/24 72.247.151.0/24 72.247.216.0/24 72.247.44.0/24 72.247.45.0/24 80.67.64.0/24 80.67.65.0/24 80.67.70.0/24 80.67.73.0/24 88.221.208.0/24 88.221.209.0/24 96.6.114.0/24"

for ip in `cat ~/Research/Targets/$1/ip.txt`; do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "[!] $ip is Known WAF" || echo "$ip" >> ~/Research/Targets/$1/ip-clean.txt
mv ~/Research/Targets/$1/ip-clean.txt ~/Research/Targets/$1/ip.txt
for ip in $(cat ~/Research/Targets/$1/$1.ip.txt);do shodan host $ip > ~/Research/Targets/$1/Shodan/$ip-shodan.txt; done 
echo "RUNNING SHODAN HOST \e[32mFINISH\e[0m "

## LAUNCH SUBJACK
echo -e "\nRUNNING \e[31m[SUBJACK]\e[0m"
subjack -w ~/Research/Targets/$1/$1.probed.txt -t 100 -a -timeout 30 -c ~/Research/Tools/Others/fingerprints.json -v -m -ssl -o ~/Research/Targets/$1/SubdomainTakeover/$1.result.txt 
echo "RUNNING SUBJACK \e[32mFINISH\e[0m "

## LAUNCH TKO-SUBS
echo -e "\nRUNNING \e[31m[TKO-SUBS]\e[0m"
tko-subs -domains=/root/Research/Targets/$1/$1.probed.txt -data=/root/Research/Tools/Others/providers-data.csv -output=/root/Research/Targets/$1/SubdomainTakeover/output.csv 
echo "RUNNING TKO-SUBS \e[32mFINISH\e[0m "

## LAUNCH WEB-ANALYZE
echo -e "\nRUNNING \e[31m[WEB-ANALYZE]\e[0m"
webanalyze -update
for a in $(cat ~/Research/Targets/$1/$1.livehosts.txt); do
	webanalyze -host $a >> ~/Research/Targets/$1/webanalyze.txt
done
rm apps.json
echo "RUNNING WEB-ANALYZE \e[32mFINISH\e[0m "

## RUNNING AQUATONE
echo -e "\nRUNNING \e[31m[AQUATONE ON SUBDOMAINS]\e[0m"
cat ~/Research/Targets/$1/$1.livehosts.txt | aquatone -threads 50 -out ~/Research/Targets/$1/Screenshots 
echo "RUNNING AQUATONE \e[32mFINISH\e[0m"

## RUNNING SMUGGLER
echo -e "\nRUNNING \e[31m[SMUGGLER]\e[0m"
python3 ~/Research/Tools/Smuggler/smuggler.py -v 1 -t 50 -u ~/Research/Targets/$1/$1.livehosts.txt >> ~/Research/Targets/$1/Smuggle/$1.Smuggled.txt 
echo "RUNNING SMUGGLER \e[32mFINISH\e[0m"

## RUNNING LINKFINDER
echo -e "\nRUNNING \e[31m[LINKFINDER]\e[0m"
sort ~/Research/Targets/$1/$1.livehosts.txt | sed 's/https\?:\/\///' | uniq >> ~/Research/Targets/$1/$1.livehosts-strip.txt
declare -a protocol=("http" "https")
for urlz in `cat ~/Research/Targets/$1/$1.livehosts-strip.txt`; do
        for protoc in ${protocol[@]}; do
                python3 ~/Research/Tools/LinkFinder/linkfinder.py -i $protoc://$urlz -d -o  ~/Research/Targets/$1/JSFiles/$protoc_$urlz-result.html 
        done
done
echo "RUNNING LINKFINDER \e[32mFINISH\e[0m"

## LAUNCH OTXURLS
echo -e "\nRUNNING \e[31m[OTXURLS]\e[0m"
cat ~/Research/Targets/$1/$1.all-final.txt | otxurls | uniq  >  ~/Research/Targets/$1/Endpoints/$1.otxurl.txt
echo "FOUND ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/$1.otxurl.txt | wc -l)]"
echo "RUNNING OTXURLS \e[32mFINISH\e[0m"

## LAUNCH WAYBACKURLS
echo -e "\nRUNNING \e[31m[WAYBACKURLS]\e[0m"
cat ~/Research/Targets/$1/$1.all-final.txt | waybackurls | uniq > ~/Research/Targets/$1/Endpoints/$1.waybackruls.txt
echo "FOUND ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/$1.waybackruls.txt | wc -l)]"
echo "RUNNING WAYBACKURLS \e[32mFINISH\e[0m"

## LAUNCH COMMONCRAWL
echo -e "\nRUNNING \e[31m[COMMONCRAWL]\e[0m"
curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$(cat ~/Research/Targets/$1/$1.domain.txt)&output=json" | jq -r .url | uniq > ~/Research/Targets/$1/Endpoints/$1.commoncrawl.txt 
echo "FOUND ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/$1.commoncrawl.txt | wc -l)]"
echo "RUNNING COMMONCRAWL \e[32mFINISH\e[0m"

## LAUNCH GITHUB ENDPOINTS
echo -e "\nRUNNING \e[31m[GITHUB ENDPOINTS]\e[0m"
for git in $(cat ~/Research/Targets/$1/$1.root.txt);do python3 ~/Research/Tools/GitHubTool/github-endpoints.py -t $github_token -d $git -s -r > ~/Research/Targets/$1/GitHub/$git-endpoints.txt; done 
echo "FOUND ENDPOINTS \e[32mFINISH\e[0m"

## REMOVING DUPLICATES
echo -e "\nTOTAL \e[31m[ENDPOINTS]\e[0m"
cat ~/Research/Targets/$1/GitHub/$1-endpoints.txt |grep -i "$1" |sort -u > ~/Research/Targets/$1/Endpoints/$1-giturls.txt
cat ~/Research/Targets/$1/Endpoints/$1-giturls.txt ~/Research/Targets/$1/Endpoints/$1.otxurl.txt ~/Research/Targets/$1/Endpoints/$1.waybackruls.txt ~/Research/Targets/$1/Endpoints/$1.commoncrawl.txt > ~/Research/Targets/$1/Endpoints/all-endpoints.txt
echo "TOTAL FOUND ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/all-endpoints.txt | wc -l)]"

## REMOVING UNIQUE
cat ~/Research/Targets/$1/Endpoints/all-endpoints.txt | qsreplace -a  > ~/Research/Targets/$1/Endpoints/unique-endpoints.txt

## SEGRAGATING JSFILES
cat ~/Research/Targets/$1/Endpoints/all-endpoints.txt | grep "\.js$" > ~/Research/Targets/$1/Endpoints/jsfles.txt
echo "TOTAL FOUND JS ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/jsfles.txt | wc -l)]"
echo "TOTAL FOUND UNIQUE ENDPOINTS [$(cat ~/Research/Targets/$1/Endpoints/unique-endpoints.txt | wc -l)]"
echo -e "\nEndpoints \e[32mCreated\e[0m "

## CREATING DICTIONARY OUT OF JS LINKS
cat ~/Research/Targets/$1/Endpoints/unique-endpoints.txt |grep linkfinder |cut -d ' ' -f2 |sed 's/\"//g' | sed 's/^[^a-zA-Z]*[0-9]*//' |sort -u > ~/Research/Targets/$1/Endpoints/dict-endpoints.txt
cat ~/Research/Targets/$1/GitHub/$1-endpoints.txt |grep -v 'http' |sed 's/^[^a-zA-Z]*[0-9]*//' |sort -u >> ~/Research/Targets/$1/Endpoints/dict-endpoints.txt
cat ~/Research/Targets/$1/Endpoints/dict-endpoints.txt |sort -u > cat ~/Research/Targets/$1/Endpoints/dict-endpoints2.txt
mv ~/Research/Targets/$1/Endpoints/dict-endpoints2.txt ~/Research/Targets/$1/Endpoints/dict-endpoints.txt
echo -e "\nDict \e[32mCreated\e[0m "

## LAUNCH GoBuster
echo -e "\nRUNNING \e[31m[GOBUSTER]\e[0m"
for go in $(cat ~/Research/Targets/$1/$1.livehosts.txt); do
       gobuster dir -u $go -e -s 200,401 -t 50 -w ~/Research/Targets/$1/Endpoints/dict-endpoints.txt >> ~/Research/Targets/$1/$1.gobuster.txt
done

## APPEND DIR BRUTE TO ENDPOINTS AND UNIQ
cat ~/Research/Targets/$1/$1.gobuster.txt |grep "Status:" |cut -d " " -f1 >> ~/Research/Targets/$1/Endpoints/unique-endpoints.txt
cat ~/Research/Targets/$1/Endpoints/unique-endpoints.txt |sort -u > ~/Research/Targets/$1/Endpoints/unique-endpoints_brute.txt
mv ~/Research/Targets/$1/Endpoints/unique-endpoints_brute.txt ~/Research/Targets/$1/Endpoints/unique-endpoints.txt
echo "RUNNING GOBUSTER \e[32mFINISH\e[0m"

## LAUNCH BRUTEX
echo -e "\nRUNNING \e[31m[BRUTEX]\e[0m"
for i in `cat ~/Research/Targets/$1/$1.probed.txt`; do
        stat_code=$(curl -s -o /dev/null -w "%{http_code}" "$i" --max-time 10)
        if [ 401 == $stat_code ]; then
                brutex $i >> ~/Research/Targets/$1/$1.brutex_creds.txt
        else
                echo "$stat_code >> $i"
        fi
done

## LAUNCH WAPITI
echo -e "\nRUNNING \e[31m[WAPITI]\e[0m"
cat ~/Research/Targets/$1/Endpoints/unique-endpoints.txt | while read url; do wapiti --scope url --flush-session -u "$url"/ -f txt -o ~/Research/Targets/$1/wapiti_$url ;done
echo "RUNNING WAPITI \e[32mFINISH\e[0m"

mv ~/Research/Targets/$1/$1.amasspassive.txt ~/Research/Targets/$1/$1.assetfinder.txt ~/Research/Targets/$1/$1.dnsbuffer.txt ~/Research/Targets/$1/$1.domain.txt ~/Research/Targets/$1/$1.livehosts-strip.txt ~/Research/Targets/$1/$1.massdns.txt ~/Research/Targets/$1/$1.probed.txt ~/Research/Targets/$1/$1.resolved.txt ~/Research/Targets/$1/$1.root.txt ~/Research/Targets/$1/$1.txt ~/Research/Targets/$1/ip.txt ~/Research/Targets/$1/$1.alldomains.txt ~/Research/Targets/$1/$1.subfinder.txt ~/Research/Targets/$1/ips.txt ~/Research/Targets/$1/$1.Crawler.txt ~/Research/Targets/$1/$1.all-final.txt ~/Research/Targets/$1/$1.gobuster.txt ~/Research/Targets/$1/Archived

}

if [ -z "$1" ]
  then
    kill
else
        recon $1
fi
