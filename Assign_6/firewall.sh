#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

declare configArray #Declare an array to store the domains from the config file.
declare ipv4Array #Declare an array to store the IPv4 addresses of the domains.
declare ipv6Array #Declare an array to store the IPv6 addresses of the domains.


# Define file names for IPv4 and IPv6 addresses
#You may use permanent files to store the IP addresses of the domains.
#However, it is recommended to use temporary files to store the IP addresses of the domains.
#This is becuase you may not have write permissions to the directory where the script is located.

    #Uuncomment the following lines if you want to use permanent files.
    #ipv4Temp="ipv4_addresses.txt"
    #ipv6Temp="ipv6_addresses.txt"

    ipv4Temp=$(mktemp) ||  echo "Error: Failed to create temporary file for IPv4"
    ipv6Temp=$(mktemp) #We are forced to use temporary files because it is possible a domain to have multiple IPv4 and IPv6 addresses.


#This function is responsible for reading the configuration files and storing them in a associative array.
function readConfigFile(){
    if [ ! -f "$config" ] ; then
        printf "The configuration file does not exist. Exiting...\n"
        exit 1
    else
    #Read the configuration file and store the domain names in the configArray.
    #Remove any trailing white spaces from the domain names.
    #Preferebly use the mapfile command to read the file.while loop will be slower.
        mapfile -t configArray < "$config"
    fi
}

function domainToIP(){
    # This function is responsible for converting domain names to IP addresses and storing them
    for domain in "${configArray[@]}"; do
        # Retrieve IPs for the domain
        #Use the host command to get the IP addresses of the domain names.
        #Use the -R 3 option to retry 3 times if the server does not respond.
        #Use Cloudflare's DNS server (1.1.1.1) for fast and quick response.
        #Use tail command to remove the first 5 lines of the output.
        #Use grep command to extract the IP addresses from the output.

        host -t A -R 3 "$domain" 1.1.1.1 |\
        tail -n +6 | \
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$ipv4Temp"& 

        pid_ipv4=$!

        host -t AAAA -R 3 "$domain" 1.1.1.1 | \
        tail -n +6 | \
        grep -Eo '(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})' >> "$ipv6Temp"&

        pid_ipv6=$!

        wait "$pid_ipv4"
        wait "$pid_ipv6"

        

    done
        mapfile -t ipv4Array < "$ipv4Temp"

        mapfile -t ipv6Array < "$ipv6Temp"

        #Remove the temporary files.
        #Comment the following line if you want to keep the temporary files.
        rm -f "$ipv4Temp" "$ipv6Temp"
    }       


function firewall() {

    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # Configure adblock rules based on domain names and IPs of $config file.
        rm -f "$ipv4Temp" "$ipv6Temp" #Remove the temporary files if they exist.
        readConfigFile
        printf "Configuring firewall rules...\n"
        domainToIP
        

        #Used for debugging purposes.
        #echo "IPv4 addresses:" "${ipv4Array[@]}"
        #echo "IPv6 addresses:" "${ipv6Array[@]}"

        # Apply firewall rules for IPv4 addresses
        for ip in "${ipv4Array[@]}"; do
            iptables -A INPUT -s "$ip" -j DROP
        done

        # Apply firewall rules for IPv6 addresses
        for ip in "${ipv6Array[@]}"; do
            ip6tables -A INPUT -s "$ip" -j DROP
        done

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $rulesV4/$rulesV6 files.

        #First, clear the rules in the files.
        truncate -s 0 "$rulesV4"
        truncate -s 0 "$rulesV6"

        #Now, save the rules to the files.
        iptables-save -f "$rulesV4"
        ip6tables-save -f "$rulesV6"

        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $rulesV4/$rulesV6 files.
        iptables-restore "$rulesV4"
        ip6tables-restore "$rulesV6"
        true

        
    elif [ "$1" = "-reset"  ]; then
    # Reset IPv4/IPv6 rules to default settings (i.e. accept all).
        for cmd in iptables ip6tables; do
            $cmd -F
            $cmd -P INPUT ACCEPT
            $cmd -P FORWARD ACCEPT
            $cmd -P OUTPUT ACCEPT
        done
        true

        
    elif [ "$1" = "-list"  ]; then
        # List IPv4/IPv6 current rules.
        
        iptables -nL #List the current rules for IPv4.Used the -n to avoid DNS lookups.
        ip6tables -nL #List the current rules for IPv6.Used the -n to avoid DNS lookups.

        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall "$1"
exit 0