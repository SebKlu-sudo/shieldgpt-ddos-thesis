# CIC-DDoS2019 - First Day Attack PCAP Cutter
# Zeiten basieren auf gematchten PCAP-Flows (UTC) + 1h CET-Korrektur
# Puffer: ~2 Minuten vor Start, ~2 Minuten nach Ende

mkdir -p ../pcap/attack

# PortMap
# echo "[1/7] Cutting PortMap..."
# editcap -F libpcap \
#  -A "2018-11-03 13:16:29" \
#  -B "2018-11-03 14:04:48" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/PortMap.pcap
# echo "      Done."

# NetBIOS
# echo "[2/7] Cutting NetBIOS..."
# editcap -F libpcap \
#  -A "2018-11-03 13:41:10" \
#  -B "2018-11-03 14:44:38" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/NetBIOS.pcap
# echo "      Done."

# LDAP
# echo "[3/7] Cutting LDAP..."
# editcap -F libpcap \
#  -A "2018-11-03 13:43:08" \
#  -B "2018-11-03 14:30:52" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/LDAP.pcap
# echo "      Done."

# MSSQL
# echo "[4/7] Cutting MSSQL..."
# editcap -F libpcap \
#  -A "2018-11-03 13:44:40" \
#  -B "2018-11-03 15:02:42" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/MSSQL.pcap
# echo "      Done."

# UDP
# echo "[5/7] Cutting UDP..."
# editcap -F libpcap \
#  -A "2018-11-03 13:44:40" \
#  -B "2018-11-03 15:02:43" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/UDP.pcap
# echo "      Done."

# UDP-Lag
# echo "[6/7] Cutting UDP-Lag..."
#editcap -F libpcap \
#  -A "2018-11-03 14:01:30" \
#  -B "2018-11-03 15:28:46" \
#  ../pcap/merged/first_day.pcap \
#  ../pcap/attack/UDP-Lag.pcap
#echo "      Done."

# SYN
echo "[7/7] Cutting SYN..."
editcap -F libpcap \
  -A "2018-11-03 13:22:34" \
  -B "2018-11-03 18:51:46" \
  ../pcap/merged/first_day.pcap \
  ../pcap/attack/SYN.pcap
echo "      Done."

echo ""
echo "================================================"
echo "PACKET COUNTS"
echo "================================================"
for f in ../pcap/attack/*.pcap; do
    echo -n "$(basename $f): "
    capinfos -c "$f" | grep "Number of packets"
done
echo "================================================"
echo "All done!"
