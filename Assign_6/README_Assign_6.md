# 📘 **Overview**

This project implements a custom firewall capable of filtering incoming packets based on user-defined rules. The firewall supports both **IPv4** and **IPv6** protocols and has been tested on **Ubuntu 24.04**. Users can define filtering rules based on domain names, which are resolved to IP addresses to facilitate the filtering process.

---

## ⚙️ **Available Options**

| **Option**  | **Description**  |
|-------------|------------------|
| `-config`   | Configures ad-blocking rules based on the domain names listed in `config.txt`. Converts domains to IP addresses and blocks them. |
| `-save`     | Saves the current firewall rules to the `rulesV4` (IPv4) and `rulesV6` (IPv6) files. |
| `-load`     | Loads firewall rules from the `rulesV4` (IPv4) and `rulesV6` (IPv6) files. |
| `-list`     | Lists the current rules for IPv4 and IPv6 using `iptables -nL` and `ip6tables -nL`. |
| `-reset`    | Resets the firewall to its default state (accept all incoming, outgoing, and forwarded connections). |
| `-help`     | Displays a help message describing the available options and usage. |

---

## ⚙️ **Execution**

The program is executed with the following command:

```bash
sudo ./firewall.sh [OPTION]
```

> **Note:** Root privileges are required for all commands listed above.

---

## 📂 **File Structure**

| **File**       | **Description** |
|----------------|-----------------|
| `firewall.sh`  | The main script containing all the logic for configuring, saving, loading, and resetting the firewall rules. |
| `config.txt`   | A list of domain names, one per line, that will be blocked when using the `-config` option. |
| `rulesV4`      | File where IPv4 rules are saved. |
| `rulesV6`      | File where IPv6 rules are saved. |

---

## 📋 **Implementation Details**

### **Domain-to-IP Resolution**

To resolve domain names to IP addresses, the script uses the `host` command. The resolved IP addresses are stored in arrays and processed by `ipv4Temp` and `ipv6Temp`, which are temporary files used to facilitate the process.

The script iterates over the IP addresses and adds them to the firewall rules using `iptables` and `ip6tables` commands. Due to the limited support for IPv6 and the goal of maintaining simplicity, a warning/error message is displayed when the user attempts to run the script with domain names that do not have an associated IPv6 address.

---

## ⚠️ **Permissions & Warnings**

- Ensure the script has **execute permissions**:
  
  ```bash
  chmod +x firewall.sh
  ```

- The script requires **root privileges** for all operations, so use `sudo` when running commands.
- **Do not modify file names** for `config.txt`, `rulesV4`, or `rulesV6`, as the script expects them to be consistent.

---

## 🔗 **References**

- [Regular expressions in grep ( regex ) with examples](https://www.cyberciti.biz/faq/grep-regular-expressions/)
- [How to Run Bash Commands in Parallel](https://linuxsimply.com/bash-scripting-tutorial/basics/executing/run-commands-in-parallel/)
- [https://www.geeksforgeeks.org/mapfile-command-in-linux-with-examples/](https://www.geeksforgeeks.org/mapfile-command-in-linux-with-examples/)
- [iptables-save command in Linux with examples](https://www.geeksforgeeks.org/iptables-save-command-in-linux-with-examples/)
