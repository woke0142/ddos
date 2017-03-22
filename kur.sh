#!/bin/bash
clear
echo "#--------------------------------------------------------#"
echo "# [ OPERGECER ] [ Gangaster034 ]   # - Teamspeak3 Kurulum Scripti #"
echo "# www.fb.com/Gangaster034 / www.fb.com/opergecer34 #"
echo "#--------------------------------------------------------#"
echo " Donusum Secenekleri"
echo "--------------------------------------"
echo -e " \033[1;32m1) \033[33m32Bit \033[1;36mKur \033[0m"
echo -e " \033[1;32m2) \033[36m64Bit \033[1;33mKur \033[0m"
echo ""
echo "------------------------------------------------------"
echo -e "\033[36mIslem Numaranizi Girin...\033[0m"
echo "------------------------------------------------------"
read secenek

case $secenek in
 1)
echo -e "32 Bit Teamspeak3 Server Kuruluyor.."
yum -y install wget
cd /home
wget http://dl.4players.de/ts/releases/3.0.10.3/teamspeak3-server_linux-x86-3.0.10.3.tar.gz
tar zxvf teamspeak3-server_linux-x86-3.0.10.3.tar.gz
rm -rf teamspeak3-server_linux-x86-3.0.10.3.tar.gz
echo "Kurulum Tamam Server Baslatiliyor !"
sleep 2
clear
chmod -R 777 teamspeak3-server_linux-x86
cd teamspeak3-server_linux-x86
sh ts3server_startscript.sh start
echo "Server Baslatildi. Lutfen asagidaki kodlari kopyalamayi unutmayiniz !"
;;
 2)
echo -e "64 Bit Teamspeak3 Server Kuruluyor.."
cd /home
yum -y install wget
wget http://dl.4players.de/ts/releases/3.0.10.3/teamspeak3-server_linux-amd64-3.0.10.3.tar.gz
tar zxvf teamspeak3-server_linux-amd64-3.0.10.3.tar.gz
rm -rf teamspeak3-server_linux-amd64-3.0.10.3.tar.gz
echo "Kurulum Tamam Server Baslatiliyor !"
sleep 2
clear
chmod -R 777 teamspeak3-server_linux-amd64
cd teamspeak3-server_linux-amd64
sh ts3server_startscript.sh start
echo "Server Baslatildi. Lutfen asagidaki kodlari kopyalamayi unutmayiniz !"
esac