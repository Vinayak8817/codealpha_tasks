# Network Intrusion Detection System (NIDS) using Snort and Grafana

## **Project Description**
This project sets up a **Linux-based Network Intrusion Detection System (NIDS)** using **Snort** for intrusion detection and **Grafana** for attack visualization. The system detects network threats and logs them for analysis.

## **Installation and Setup**
### **1. System Requirements**
- Linux (Ubuntu/CentOS)
- Snort
- Grafana
- InfluxDB
- Telegraf
- Barnyard2
- jq, curl

### **2. Installation Steps**
#### **Step 1: Clone the Repository**
```bash
git clone https://github.com/your-username/linux-nids-snort-grafana.git
cd linux-nids-snort-grafana
```

#### **Step 2: Grant Execution Permissions**
```bash
chmod +x setup_nids.sh
```

#### **Step 3: Run the Script**
```bash
sudo ./setup_nids.sh
```

#### **Step 4: Verify the Setup**
- **Snort**: Check if Snort is running properly:
  ```bash
  sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
  ```
- **Grafana**: Open a web browser and go to:
  ```
  http://localhost:3000
  ```
  (Default login: **admin/admin**)
- **InfluxDB**: Verify database creation:
  ```bash
  curl -XPOST "http://localhost:8086/query" --data-urlencode "q=SHOW DATABASES"
  ```

## **Script: setup_nids.sh**
```bash
#!/bin/bash
# Network Intrusion Detection System (NIDS) using Snort and Grafana
# Author: Pratik Walunj
# Description: This script sets up Snort for intrusion detection and configures Grafana for attack visualization.

# Step 1: Update System and Install Dependencies
echo "Updating system and installing dependencies..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y snort grafana influxdb telegraf barnyard2 jq curl

# Step 2: Configure Snort
echo "Configuring Snort..."
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
sudo sed -i 's/include $RULE_PATH/#include $RULE_PATH/' /etc/snort/snort.conf
echo "include /etc/snort/rules/local.rules" | sudo tee -a /etc/snort/snort.conf

# Step 3: Add Sample Snort Rule
echo "Creating a test rule for detecting ICMP traffic..."
echo "alert icmp any any -> any any (msg:\"ICMP detected\"; sid:1000001; rev:1;)" | sudo tee /etc/snort/rules/local.rules

# Step 4: Enable Snort Logging
echo "Enabling Snort logging..."
sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert
sudo chmod 777 /var/log/snort/alert

# Step 5: Configure Barnyard2
echo "Configuring Barnyard2..."
sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo

# Step 6: Configure InfluxDB for Storing Logs
echo "Configuring InfluxDB..."
sudo systemctl start influxdb
sudo systemctl enable influxdb
curl -XPOST "http://localhost:8086/query" --data-urlencode "q=CREATE DATABASE snort_logs"

# Step 7: Configure Telegraf for Data Collection
echo "Configuring Telegraf..."
echo "[[inputs.tail]]
  files = [\"/var/log/snort/alert\"]
  from_beginning = true
  name_override = \"snort_alerts\"
  data_format = \"influx\"
  tag_keys = [\"severity\"]" | sudo tee -a /etc/telegraf/telegraf.conf

sudo systemctl restart telegraf
sudo systemctl enable telegraf

# Step 8: Configure Grafana Dashboard
echo "Setting up Grafana dashboard..."
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

# Step 9: Start Snort in NIDS Mode
echo "Starting Snort in NIDS mode..."
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

echo "Network Intrusion Detection System setup is complete!"
echo "Access Grafana at http://localhost:3000 (default user: admin, password: admin)"
echo "Use InfluxDB as the data source to visualize Snort alerts."
```
