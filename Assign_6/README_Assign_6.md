# 📘 **Overview**

This project implements a custom firewall capable of filtering incoming packets based on user-defined rules. The firewall supports both **IPv4** and **IPv6** protocols and has been tested on **Ubuntu 24.04**. Users can define filtering rules based on domain names, which are resolved to IP addresses to facilitate the filtering process.

---

## **Available Options**

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

The program begins by verifying if the user has root privileges. If not, it displays an error message and terminates the execution. It then processes the command-line arguments and executes the corresponding actions based on the user's selection.

The script filters the configuration file to identify any existing IP addresses (both IPv4 and IPv6) and stores them in separate arrays. These IPs are later used to define firewall rules. Following this, the script converts domain names specified in the configuration file into their respective IP addresses and adds them to the appropriate arrays (IPv4 or IPv6).

Once the IPs are collected, the program applies all the discovered addresses as firewall rules. It then saves these rules to the appropriate files for persistence. Additionally, the user has the option to delete any IPs that were initially detected in the configuration file.

To ensure a clean output and avoid confusion, stderr is redirected to /dev/null, suppressing potential error messages. This decision is justified by the relatively low adoption rate of the IPv6 protocol, minimizing the impact of missing or unresolvable IPv6 addresses.

**Note** that the if the configuration file contains IP addresses, the script will collect them and remove them from the configuration file. This is done to prevent false entries in the firewall rules.

---

## ⚠️ **Permissions & Warnings**

- Ensure the script has **execute permissions**:
  
  ```bash
  chmod +x firewall.sh
  ```

- The script requires **root privileges** for all operations, so use `sudo` when running commands.
- **Do not modify file names** for `config.txt`, `rulesV4`, or `rulesV6`, as the script expects them to be consistent.

---

## Blocking effect of the firewall

Upon visiting our favorite website, we can observe that most ads have disappeared. This is because the firewall has successfully blocked the IP addresses associated with ad servers. However, some ads may still be displayed if their corresponding IP addresses were not included in the configuration file and, as a result, were not blocked by the firewall.

---

## 🔗 **References**

- [Regular expressions in grep ( regex ) with examples](https://www.cyberciti.biz/faq/grep-regular-expressions/)
- [How to Run Bash Commands in Parallel](https://linuxsimply.com/bash-scripting-tutorial/basics/executing/run-commands-in-parallel/)
- [https://www.geeksforgeeks.org/mapfile-command-in-linux-with-examples/](https://www.geeksforgeeks.org/mapfile-command-in-linux-with-examples/)
- [iptables-save command in Linux with examples](https://www.geeksforgeeks.org/iptables-save-command-in-linux-with-examples/)
- [How to concatenate arrays in bash?](https://stackoverflow.com/questions/31143874/how-to-concatenate-arrays-in-bash)
