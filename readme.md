For Snort 3, you'll need to adjust your commands and configurations slightly compared to Snort 2.x due to changes in configuration handling and rule syntax. Here’s a step-by-step guide on how to set up your environment, create rules, and run Snort 3 with those rules.

### 1. **Create Your Rule File**
Create a rule file with a specific name based on your requirements, such as `<rulefile_roll_no>.rules`, and write your rules in the Snort 3 format. Here is an example of how your rules might look:

```plaintext
# FTP traffic with SYN flag
alert tcp any any -> $HOME_NET 21 ( msg:"Attempt to FTP to server."; flags:S; sid:1000001; )

# Incoming ICMP Echo (ping)
alert icmp any any -> $HOME_NET any ( msg:"Attempt to ping the server."; itype:8; sid:1000002; )

# Telnet traffic with SYN flag
alert tcp any any -> $HOME_NET 23 ( msg:"Attempt to telnet to server."; flags:S; sid:1000003; )

# SSH traffic containing "SSH-2"
alert tcp any 22 -> $HOME_NET 22 (
    msg:"Attempt to SSH to server.";
    content:"SSH-2",fast_pattern;
    sid:1000004;
)


# HTTP traffic with SYN flag
alert tcp any any -> $HOME_NET 80 ( msg:"Attempt to http to server."; flags:S; sid:1000005; )

# DNS query for "ubuntu"
alert udp any any -> $HOME_NET 53 ( msg:"DNS Query Ubuntu."; content:"ubuntu" ,fast_pattern; sid:1000006; )

# Any traffic containing "secret.txt"
alert ip any any -> $HOME_NET any ( msg:"Found secret.txt."; content:"secret.txt",fast_pattern; sid:1000007; )

# SSH traffic with FIN and ACK flags
alert tcp any any -> $HOME_NET 22 (msg:"F/A for SSH teardown."; flags:FA; sid:1000008;)

```
Replace `$HOME_NET` with the appropriate network or IP range you're monitoring. 

### 2. **Configuration File Adjustments**
Make sure your `snort.lua` or equivalent configuration file includes the path to your rules file. You might add something like this:

```lua

** Remember that only last rule will run so you have comment and uncomment accordingly. **
ips = {
     include = '/opt/home/etc/snort/rules/FTP_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/ping_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/telnet_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/SSH2_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/http_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/dns_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/secret_rulefile_2101086.rules',
    include = '/opt/home/etc/snort/rules/ssh_finack_rulefile_2101086.rules',
}
```

### 3. **Running Snort**
Use the following command to run Snort 3 with your rules against a pcap file:

```bash
snort -c  /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_full/alert_fast/alert_csv/alert_syslog/alert_sfsocket
```

- `-c /path/to/snort.lua` points to your configuration file.
- `-r /path/to/pcapfile.pcap` specifies the pcap file you want to analyze.
- `--alert-before-pass` ensures alert rules are evaluated before pass rules.
- `-A cmg` directs output to the console, but you can redirect it to files if needed.

### 4. **Output to a File**
To redirect the console output to a file for later analysis or as part of your submission, you can modify the command like this:

```bash
snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/ftp_output_file.txt


snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/output_file.txt


snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_full > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/output_file.txt

snort -c  /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A cmg     
--> cmg for console

*** For particular rule you comment and uncomment that rule in snort.lua ***

1. For alert on any ftp traffic with the SYN flag set to the server. Message should read: “Attempt to FTP to server.”

  snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/ftp_output_file.txt

2. For alert on any incoming pings to the server. Message should read: “Attempt to ping the server.” 

   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/ping_output_file.txt

3. For alert on any telnet traffic with the SYN flag set to the server.Message should read: “Attempt to telnet to   server.”

   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/telnet_output_file.txt

4. For alert on any ssh traffic containing keyword “SSH-2” to the server. Message should read: “Attempt to SSH to server.”
   
   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/ssh2_output_file.txt

5. For Alert on any http traffic with the SYN flag set to the server.Message should read: “Attempt to http to server.”
   
   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/http_output_file.txt


6. For alert on any DNS traffic to the local DNS server that contains the keyword “ubuntu”. Message should read: “DNS Query Ubuntu.”
   
   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/dns_output_file.txt

7. For alert on any packet to the server that contains the text “secret.txt”. Message should read: “Found secret.txt.”
   
   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/secret_output_file.txt


8. For alert on any SSH traffic to the server with the FIN and ACK flags set. Message should read: “F/A for SSH teardown.”

   snort -c /opt/home/etc/snort/snort.lua -r /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/all_traffic.pcap --alert-before-pass -A alert_fast > /Users/hritik/iiitg/semester/6th_sem/Computer_security/Assignment2_snort/ssh_finack_output_file.txt

```

This will save all console outputs to `output_file.txt`, which includes alerts triggered by your rules.

### 5. **Validate Configuration**
You can test your Snort configuration without processing any packets by using:

```bash
snort -c /opt/home/etc/snort/snort.lua  --warn-all
snort -c /opt/home/etc/snort/snort.lua  -T

```

This command checks the configuration for errors and displays warnings for potential issues without running the detection engine.

### 6. **Final Notes**
- Make sure all paths are correct and accessible by the user running Snort.
- If Snort doesn't run as expected, check the permissions of the pcap files and the rule file, as well as network interface access permissions.
- Review logs for error messages that can provide additional insights into configuration issues or rule syntax errors.