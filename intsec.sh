#!/bin/bash
# NESSUS-LEVEL VULNERABILITY SCANNER WITH NVD INTEGRATION
# Comprehensive service enumeration and CVE detection

SCAN_DIR="/tmp/nessus_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SCAN_DIR"

log() { echo "[*] $1"; }
success() { echo "[+] $1"; }
error() { echo "[-] $1"; }

SERVER_PORTS="21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,1723,1883,2049,2082,2083,2086,2087,2095,2096,2375,2376,3000,3306,3389,5432,5601,5672,5900,5938,5984,5985,5986,6379,7001,7002,7199,8000,8008,8009,8080,8081,8088,8090,8091,8140,8143,8161,8172,8180,8200,8222,8243,8280,8281,8333,8443,8500,8530,8531,8800,8834,8880,8888,9000,9001,9042,9060,9080,9090,9091,9100,9160,9200,9300,9443,9600,9673,9675,9678,9680,9980,9981,9999,10000,11211,15672,27017,28017,50000,50070,50075,61616"
# ----------------------------
# GLOBAL CONCURRENCY LIMITER
# ----------------------------
MAX_JOBS=6   # safe for corporate networks

run_limited() {
    # allow only MAX_JOBS at a time
    while true; do
        running=$(jobs -rp | wc -l)
        if [ "$running" -lt "$MAX_JOBS" ]; then
            break
        fi
        sleep 0.2
    done

    "$@" &
}

# NVD API function
query_nvd() {
    local cpe="$1"
    local api_key="${2:-}"
    
    local encoded_cpe=$(echo "$cpe" | sed 's/:/%3A/g' | sed 's/\//%2F/g')
    local url="https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$encoded_cpe"
    
    if [ -n "$api_key" ]; then
        curl -s -H "apiKey: $api_key" "$url"
    else
        curl -s "$url"
    fi
}

# Extract CPEs from nmap output
extract_cpes() {
    log "Extracting CPE information"
    
    # Method 1: Extract CPEs from nmap XML
    if [ -f "$SCAN_DIR/services.xml" ]; then
        grep -o "cpe:[^\"]*" "$SCAN_DIR/services.xml" | sort -u > "$SCAN_DIR/cpes.txt"
    fi
    
    # Method 2: Generate CPEs from service detection
    grep -E "Product:|Version:" "$SCAN_DIR/services.nmap" 2>/dev/null | \
    awk 'BEGIN{p="";v=""} 
         /Product:/{p=$2} 
         /Version:/{v=$2; if(p&&v){
             gsub(/ /, "_", p);
             gsub(/ /, "_", v);
             print "cpe:/a:" tolower(p) ":" tolower(p) ":" v;
             p="";v=""
         }}' | sort -u >> "$SCAN_DIR/cpes.txt"
    
    sort -u "$SCAN_DIR/cpes.txt" -o "$SCAN_DIR/cpes.txt"
    success "Found $(wc -l < "$SCAN_DIR/cpes.txt") unique CPEs"
}

# Query NVD for CVEs
query_nvd_cves() {
    local api_key="$1"
    log "Querying NVD API for CVEs"
    
    > "$SCAN_DIR/nvd_cves.json"
    > "$SCAN_DIR/cve_findings.txt"
    
    while read cpe; do
        if [ -n "$cpe" ]; then
            log "Querying CPE: $cpe"
            response=$(query_nvd "$cpe" "$api_key")
            
            if [ -n "$response" ]; then
                echo "$response" | jq -r '.vulnerabilities[]? | .cve.id + " | " + .cve.descriptions[0].value' 2>/dev/null >> "$SCAN_DIR/cve_findings.txt"
                echo "$response" >> "$SCAN_DIR/nvd_cves.json"
            fi
            
            # Rate limiting
            if [ -z "$api_key" ]; then
                sleep 6
            else
                sleep 1
            fi
        fi
    done < "$SCAN_DIR/cpes.txt"
    
    success "CVE detection complete"
}

# 1. SMART PORT DISCOVERY
discover_ports() {
    local target="$1"
    log "Port Discovery: $target"
    
    if [[ "$target" == *"/"* ]]; then
        log "Network range - masscan"
        masscan -p "$SERVER_PORTS" "$target" --rate=1000 -oG "$SCAN_DIR/masscan.txt" 2>/dev/null
        awk '/open/{print $2}' "$SCAN_DIR/masscan.txt" | sort -u > "$SCAN_DIR/live_hosts.txt"
    elif [[ "$target" == *,* ]]; then
        log "Multiple IPs - nmap"
        nmap -n -p "$SERVER_PORTS" --open -iL <(echo "$target" | tr ',' '\n') -oG - 2>/dev/null | awk '/open/{print $2}' | sort -u > "$SCAN_DIR/live_hosts.txt"
    else
        log "Single IP - nmap"
        nmap -n -p "$SERVER_PORTS" --open "$target" -oG - 2>/dev/null | awk '/open/{print $2}' | sort -u > "$SCAN_DIR/live_hosts.txt"
    fi
    
    [ ! -s "$SCAN_DIR/live_hosts.txt" ] && error "No hosts found" && return 1
    success "Found $(wc -l < "$SCAN_DIR/live_hosts.txt") hosts"
}

# 2. SERVICE DETECTION
detect_services() {
    log "Service Detection"
    nmap -sV -sC -A -iL "$SCAN_DIR/live_hosts.txt" -oA "$SCAN_DIR/services" 2>/dev/null
    success "Service detection complete"
}

# 3. CVE DETECTION WITH NVD API
detect_cves() {
    local api_key="$1"
    log "CVE Detection via NVD API"
    
    extract_cpes
    query_nvd_cves "$api_key"
    
    # Also run searchsploit for local exploit database
    log "Searching for local exploits..."
    > "$SCAN_DIR/exploits.txt"
    while read cpe; do
        product=$(echo "$cpe" | cut -d: -f4)
        [ -n "$product" ] && searchsploit "$product" 2>/dev/null | grep -v "No Results" >> "$SCAN_DIR/exploits.txt"
    done < "$SCAN_DIR/cpes.txt"
}

# 4. NESSUS-LEVEL SERVICE ENUMERATION
enumerate_services() {
    log "Nessus-Level Service Enumeration"

    while read host; do
        sleep 0.4   # Reduce burst noise, 0.4s is perfect

        ports=$(grep -A100 "Nmap scan report for $host" "$SCAN_DIR/services.nmap" 2>/dev/null | \
                grep -E "^[0-9]+/tcp.*open" | awk '{print $1}' | cut -d'/' -f1)

        for port in $ports; do
            case $port in

                # WEB SERVICES
                80|443|8080|8081|8088|8090|8443|7443|9443)
                    log "Web Deep Enum: $host:$port"
                    [ -x "$(command -v nikto)" ] && run_limited nikto -h "$host" -p "$port" -C all -o "$SCAN_DIR/nikto_${host}_${port}.txt"
                    [ -x "$(command -v dirsearch)" ] && run_limited dirsearch -u "http://$host:$port" -e php,asp,aspx,jsp,html,txt,json,config -o "$SCAN_DIR/dirsearch_${host}_${port}.txt"
                    [ -x "$(command -v whatweb)" ] && run_limited bash -c "whatweb -a 3 'http://$host:$port' > '$SCAN_DIR/whatweb_${host}_${port}.txt'"
                    run_limited nmap --script "http-vuln*,http-enum,http-headers,http-methods,http-auth" -p "$port" "$host" -oN "$SCAN_DIR/web_scan_${host}_${port}.txt"
                    ;;

                # SMB/CIFS
                445|139)
                    log "SMB Deep Enum: $host"
                    run_limited nmap --script "smb-vuln*,smb-security-mode,smb-enum-shares,smb-os-discovery,smb-enum-users,smb-enum-groups,smb-enum-sessions,smb-enum-domains,smb-server-stats,smb-protocols,smb2-security-mode,smb2-capabilities" -p "$port" "$host" -oN "$SCAN_DIR/smb_full_${host}.txt"
                    [ -x "$(command -v enum4linux)" ] && run_limited enum4linux -a "$host" > "$SCAN_DIR/enum4linux_${host}.txt"
                    [ -x "$(command -v smbmap)" ] && run_limited smbmap -H "$host" > "$SCAN_DIR/smbmap_${host}.txt"
                    ;;

                # SSH
                22)
                    log "SSH Deep Enum: $host"
                    [ -x "$(command -v ssh-audit)" ] && run_limited ssh-audit "$host" > "$SCAN_DIR/sshaudit_${host}.txt"
                    run_limited nmap --script "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,sshv1" -p 22 "$host" -oN "$SCAN_DIR/ssh_full_${host}.txt"
                    ;;

                # RDP
                3389)
                    log "RDP Deep Enum: $host"
                    run_limited nmap --script "rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020" -p 3389 "$host" -oN "$SCAN_DIR/rdp_full_${host}.txt"
                    ;;

                # FTP
                21)
                    log "FTP Deep Enum: $host"
                    run_limited nmap --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor" -p 21 "$host" -oN "$SCAN_DIR/ftp_full_${host}.txt"
                    ;;

                # SMTP
                25|587|465)
                    log "SMTP Deep Enum: $host"
                    run_limited nmap --script "smtp-commands,smtp-enum-users,smtp-open-relay,smtp-strangeport,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764" -p "$port" "$host" -oN "$SCAN_DIR/smtp_full_${host}.txt"
                    ;;

                # DNS
                53)
                    log "DNS Deep Enum: $host"
                    run_limited nmap --script "dns-recursion,dns-cache-snoop,dns-service-discovery,dns-zone-transfer,dns-update,dns-nsid" -p 53 -sU "$host" -oN "$SCAN_DIR/dns_full_${host}.txt"
                    [ -x "$(command -v dnsrecon)" ] && run_limited dnsrecon -d "$host" -n "$host" > "$SCAN_DIR/dnsrecon_${host}.txt"
                    ;;

                # DATABASES
                1433)
                    log "MSSQL Deep Enum: $host"
                    run_limited nmap --script "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-dump-hashes,ms-sql-query,ms-sql-tables,ms-sql-hasdbaccess" -p 1433 "$host" -oN "$SCAN_DIR/mssql_full_${host}.txt"
                    ;;
                3306)
                    log "MySQL Deep Enum: $host"
                    run_limited nmap --script "mysql-info,mysql-empty-password,mysql-enum,mysql-databases,mysql-variables,mysql-audit,mysql-brute" -p 3306 "$host" -oN "$SCAN_DIR/mysql_full_${host}.txt"
                    ;;
                5432)
                    log "PostgreSQL Deep Enum: $host"
                    run_limited nmap --script "pgsql-brute,pgsql-info" -p 5432 "$host" -oN "$SCAN_DIR/postgres_full_${host}.txt"
                    ;;
                1521)
                    log "Oracle Deep Enum: $host"
                    run_limited nmap --script "oracle-sid-brute,oracle-enum-users" -p 1521 "$host" -oN "$SCAN_DIR/oracle_full_${host}.txt"
                    ;;

                # NOSQL DATABASES
                27017)
                    log "MongoDB Deep Enum: $host"
                    run_limited nmap --script "mongodb-info,mongodb-databases,mongodb-brute" -p 27017 "$host" -oN "$SCAN_DIR/mongodb_full_${host}.txt"
                    ;;
                6379)
                    log "Redis Deep Enum: $host"
                    run_limited nmap --script "redis-info,redis-brute" -p 6379 "$host" -oN "$SCAN_DIR/redis_full_${host}.txt"
                    ;;
                9200)
                    log "Elasticsearch Deep Enum: $host"
                    run_limited nmap --script "elasticsearch-info" -p 9200 "$host" -oN "$SCAN_DIR/elasticsearch_full_${host}.txt"
                    ;;
                11211)
                    log "Memcached Deep Enum: $host"
                    run_limited nmap --script "memcached-info" -p 11211 -sU "$host" -oN "$SCAN_DIR/memcached_full_${host}.txt"
                    ;;

                # MESSAGE QUEUES
                5672)
                    log "RabbitMQ Enum: $host"
                    run_limited nmap --script "amqp-info" -p 5672 "$host" -oN "$SCAN_DIR/rabbitmq_${host}.txt"
                    ;;
                61616)
                    log "ActiveMQ Enum: $host"
                    run_limited nmap --script "amqp-info" -p 61616 "$host" -oN "$SCAN_DIR/activemq_${host}.txt"
                    ;;

                # VIRTUALIZATION/CLOUD
                2375|2376)
                    log "Docker Enum: $host"
                    run_limited nmap --script "docker-version" -p "$port" "$host" -oN "$SCAN_DIR/docker_${host}.txt"
                    ;;
                5985|5986)
                    log "WinRM Enum: $host"
                    run_limited nmap --script "winrm-info,http-auth,http-methods" -p "$port" "$host" -oN "$SCAN_DIR/winrm_${host}.txt"
                    ;;

                # ENTERPRISE APPS
                7001|7002)
                    log "WebLogic Enum: $host"
                    run_limited nmap --script "weblogic-t3-info,http-enum" -p "$port" "$host" -oN "$SCAN_DIR/weblogic_${host}.txt"
                    ;;
                9042)
                    log "Cassandra Enum: $host"
                    run_limited nmap --script "cassandra-info,cassandra-brute" -p 9042 "$host" -oN "$SCAN_DIR/cassandra_${host}.txt"
                    ;;
                50000|50070|50075)
                    log "Hadoop Enum: $host"
                    run_limited nmap --script "hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info" -p "$port" "$host" -oN "$SCAN_DIR/hadoop_${host}.txt"
                    ;;

                # NETWORK SERVICES
                23)
                    log "Telnet Enum: $host"
                    run_limited nmap --script "telnet-encryption,telnet-ntlm-info" -p 23 "$host" -oN "$SCAN_DIR/telnet_${host}.txt"
                    ;;
                111)
                    log "RPC Enum: $host"
                    run_limited nmap --script "rpcinfo" -p 111 "$host" -oN "$SCAN_DIR/rpc_${host}.txt"
                    ;;
                135)
                    log "RPC/DCE Enum: $host"
                    run_limited nmap --script "rpcinfo" -p 135 "$host" -oN "$SCAN_DIR/dcerpc_${host}.txt"
                    ;;

                # MANAGEMENT SERVICES
                5900)
                    log "VNC Enum: $host"
                    run_limited nmap --script "vnc-info,vnc-title" -p 5900 "$host" -oN "$SCAN_DIR/vnc_${host}.txt"
                    ;;
                5984)
                    log "CouchDB Enum: $host"
                    run_limited nmap --script "couchdb-databases,couchdb-stats" -p 5984 "$host" -oN "$SCAN_DIR/couchdb_${host}.txt"
                    ;;
                8009)
                    log "AJP Enum: $host"
                    run_limited nmap --script "ajp-methods,ajp-request" -p 8009 "$host" -oN "$SCAN_DIR/ajp_${host}.txt"
                    ;;
            esac
        done
    done < "$SCAN_DIR/live_hosts.txt"

    wait
    success "Nessus-level enumeration complete"
}

# WINDOWS OS ENUMERATION (NO CREDS, NESSUS-STYLE)
detect_windows_os() {
    log "Detecting Windows OS & EOL Status"

    OUT="$SCAN_DIR/os_findings.txt"
    > "$OUT"

    while read host; do
        log "OS Enum: $host"

        # Extract OS from SMB discovery
        os_line=$(grep -A5 "Nmap scan report for $host" "$SCAN_DIR/services.nmap" \
            | grep "OS:" | head -1)

        # Extract from SMB OS script output
        smb_file="$SCAN_DIR/smb_full_${host}.txt"
        if [ -f "$smb_file" ]; then
            smb_os=$(grep -i "OS:" "$smb_file" | head -1)
        fi

        # Extract RDP version
        rdp_file="$SCAN_DIR/rdp_full_${host}.txt"
        if [ -f "$rdp_file" ]; then
            rdp_version=$(grep -i "RDP" "$rdp_file" | head -1)
        fi

        detected_os="${os_line:-$smb_os}"
        detected_os="${detected_os:-$rdp_version}"

        if [ -z "$detected_os" ]; then
            echo "$host | UNKNOWN OS" >> "$OUT"
            continue
        fi

        # Normalize OS text
        clean_os=$(echo "$detected_os" | sed 's/OS: //g' | sed 's/^ *//')

        # EOL classification
        case "$clean_os" in
            *"Windows 7"*|*"2008 R2"*|*"2008 Server"*)
                status="EOL — Vulnerable (Critical)"
                ;;

            *"Windows Server 2012 R2"*|*"2012"*)
                status="EOL — Unsupported (Critical)"
                ;;

            *"Windows Server 2016"*)
                status="Supported but Outdated (Medium)"
                ;;

            *"Windows Server 2019"*)
                status="Supported (Low)"
                ;;

            *"Windows Server 2022"*)
                status="Fully Supported (OK)"
                ;;

            *"Windows 10 1507"*|*"1511"*|*"1607"*|*"1703"*|*"1709"*|*"1803"*|*"1809"*|*"1903"*)
                status="Windows 10 (EOL build) — Critical"
                ;;

            *"Windows 10"*|*"Windows 11"*)
                status="Supported (depends on build)"
                ;;

            *)
                status="Unknown Support Status"
                ;;
        esac

        echo "$host | $clean_os | $status" >> "$OUT"

    done < "$SCAN_DIR/live_hosts.txt"

    success "Windows OS + EOL detection complete → $OUT"
}
# WINDOWS PATCH LEVEL INFERENCE (NO CREDS)
infer_windows_patch_level() {
    log "Inferring Windows Patch Levels from Build Numbers"

    IN="$SCAN_DIR/os_findings.txt"
    OUT="$SCAN_DIR/windows_patch_levels.txt"
    > "$OUT"

    while read line; do
        host=$(echo "$line" | cut -d"|" -f1 | tr -d ' ')
        os=$(echo "$line" | cut -d"|" -f2- | sed 's/^ *//' | sed 's/|.*//')

        # Extract build number
        build=$(echo "$os" | grep -oE "[0-9]{4,6}" | head -1)

        if [ -z "$build" ]; then
            echo "$host | $os | Build: Unknown | Patch Level: Unknown" >> "$OUT"
            continue
        fi

        # PATCH MAPPING
        patch="Unknown"

        # Windows Server 2008 R2 / Windows 7 (EOL)
        if [ "$build" -eq 7601 ]; then
            patch="EOL — No security patches since Jan 2020"

        # Windows Server 2012 R2 (EOL)
        elif [ "$build" -eq 9600 ]; then
            patch="EOL — No security patches since Oct 2023"

        # Windows 10 / Server 2016 / 2019 / 2022 based on build
        # Windows 10 1507 → 10240
        elif [ "$build" -eq 10240 ]; then patch="Windows 10 1507 — EOL"
        elif [ "$build" -eq 10586 ]; then patch="Windows 10 1511 — EOL"
        elif [ "$build" -eq 14393 ]; then patch="Server 2016 / Win10 1607 — Last patch: 2023-11"
        elif [ "$build" -eq 15063 ]; then patch="Windows 10 1703 — EOL"
        elif [ "$build" -eq 16299 ]; then patch="Windows 10 1709 — EOL"
        elif [ "$build" -eq 17134 ]; then patch="Windows 10 1803 — EOL"
        elif [ "$build" -eq 17763 ]; then patch="Server 2019 / Win10 1809 — Last patch: 2024-01"
        elif [ "$build" -eq 18362 ]; then patch="Windows 10 1903 — EOL"
        elif [ "$build" -eq 18363 ]; then patch="Windows 10 1909 — EOL"
        elif [ "$build" -eq 19041 ]; then patch="Win10 2004 / Win10 20H1 — Patches until 2025"
        elif [ "$build" -eq 19042 ]; then patch="Win10 20H2 — EOL"
        elif [ "$build" -eq 19043 ]; then patch="Win10 21H1 — EOL"
        elif [ "$build" -eq 19044 ]; then patch="Win10 21H2 — Patches until 2026"
        elif [ "$build" -eq 20348 ]; then patch="Windows Server 2022 — Fully supported"
        elif [ "$build" -eq 22000 ]; then patch="Windows 11 — Supported"
        elif [ "$build" -eq 22621 ]; then patch="Windows 11 22H2 — Supported"
        fi

        echo "$host | $os | Build: $build | Patch Level: $patch" >> "$OUT"

    done < "$IN"

    success "Windows build → patch mapping complete → $OUT"
}
# PASSIVE WINDOWS CVE TAGGING BASED ON VERSION (SAFE)
tag_windows_cves() {
    log "Tagging Windows versions with known CVE families (safe passive mapping)"

    IN="$SCAN_DIR/windows_patch_levels.txt"
    OUT="$SCAN_DIR/windows_cve_tags.txt"
    > "$OUT"

    while read line; do
        host=$(echo "$line" | cut -d"|" -f1 | tr -d ' ')
        os=$(echo "$line" | cut -d"|" -f2- | cut -d"|" -f1 | sed 's/^ *//')
        build=$(echo "$line" | grep -oE "Build: [0-9]{4,6}" | awk '{print $2}')

        CVES="None"

        #############################
        # WINDOWS 7 / 2008 R2 (7601)
        #############################
        if echo "$build" | grep -q "^7601$"; then
            CVES="MS17-010 (EternalBlue), BlueKeep, PrintNightmare, Zerologon (domain exposure), CVE-2019-0708"

        #############################
        # WINDOWS 2012 R2 (9600)
        #############################
        elif echo "$build" | grep -q "^9600$"; then
            CVES="PrintNightmare, BlueKeep family, NTLM Relay, SMB Signing Disabled Risks"

        #############################
        # SERVER 2016 / WIN10 1607 (14393)
        #############################
        elif echo "$build" | grep -q "^14393$"; then
            CVES="PrintNightmare, PetitPotam, Certifried, WebDAV NTLM leaks, RDP Cred Guard bypass CVEs"

        #############################
        # SERVER 2019 / WIN10 1809 (17763)
        #############################
        elif echo "$build" | grep -q "^17763$"; then
            CVES="Zerologon (CVE-2020-1472), PrintNightmare, PetitPotam, DFSCoerce family"

        #############################
        # WINDOWS 10 2004 / 20H1 (19041)
        #############################
        elif echo "$build" | grep -q "^19041$"; then
            CVES="PrintNightmare, MSRPC NTLM relay CVEs, Active Directory LSA spoofing CVEs"

        #############################
        # WINDOWS 11 / SERVER 2022
        #############################
        elif echo "$build" | grep -q "^20348$"; then
            CVES="PrintNightmare (if unpatched), CVE-2022 SMB compression issues"

        #############################
        # UNKNOWN
        #############################
        else
            CVES="Unclassified"
        fi

        echo "$host | $os | Build $build | CVE Families: $CVES" >> "$OUT"

    done < "$IN"

    success "Windows CVE family tagging complete → $OUT"
}

# MAIN
main() {
    target="${1:-}"
    api_key="${2:-}"
    
    [ -z "$target" ] && read -p "Enter target: " target
    [ -z "$target" ] && error "No target" && exit 1
    
    if [ -z "$api_key" ]; then
        read -p "NVD API key (optional, for higher rate limits): " api_key
    fi
    
    log "Starting Nessus-Level Scan: $target"
    
    discover_ports "$target" || exit 1
    detect_services
    detect_cves "$api_key"
    detect_windows_os
    infer_windows_patch_level
    tag_windows_cves
    enumerate_services
    
    success "Scan Complete: $SCAN_DIR"
    echo "CVEs: $SCAN_DIR/cve_findings.txt"
    echo "Exploits: $SCAN_DIR/exploits.txt"
    echo "Services: $SCAN_DIR/services.nmap"
    echo "Full results in: $SCAN_DIR"
}

main "$@"
