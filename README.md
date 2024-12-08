# Using-Nmap-to-Scan-the-Network-for-Available-Host

### OBJECTIVE

In this task, the network will be scanned to detect the available hosts using the Nmap application

# STEPS

### TASK 1

Using the XAMPP Control Panel, I started the Apache and MySQL
![image](https://github.com/user-attachments/assets/03193f70-2731-40a8-9328-3721941838c7)

A vulnerable web server has been configured on ACIDM01. It will be scanned to determine the exposed ports and vulnerabilities.


2. Connected to the Kali Purple Machine, opened the Terminal and executed a command to display the devices's IP address and subnet mask which will be used to scan the network for connected device
   
4. ![image](https://github.com/user-attachments/assets/ba53dacd-b2c6-490b-8196-8d95174db8b3)

Executed the command to display all the active devices connected to the specified subnet. The detected devices can be scanned individually to detect open ports and running services. From the results, it can be seen that six devices with their associated IP addresses have been detected.

![image](https://github.com/user-attachments/assets/bf7a25c8-a90d-4a63-a158-fbe03a026964)


![image](https://github.com/user-attachments/assets/ea00127e-c75b-42fb-89c7-936884b3fc12)

The open ports on the device are displayed. From the results, it was determined that Port 80 is open, which might indicate that the device is a web server.

Executed command that displays the open ports on the device.

![image](https://github.com/user-attachments/assets/b52e2016-5319-40f9-b1f2-22d1f4191d83)


### Task 2 - Scan Detected Hosts for Vulnerabilities with Nikto

In this task, I used the Nikto applciation to detect host which will be scanned fo rvulnerabilties

In the Terminal in Kali purple, I nstalled the nikto application

![image](https://github.com/user-attachments/assets/b72d0bd2-2e25-4286-a32d-b15b9a8bb4ca)


Executed a command to display the version of the   Apache server running on the device as 2.4.56. This can be used to determine if there are any discovered vulnerabilities for the specific version

![image](https://github.com/user-attachments/assets/d336a151-7629-4acc-8fa0-ec4da0ee9b16)

 In Task 1, the 192.168.0.4 device was scanned, showing that Port 9000 was open. When scanning the device with the Nikto application, it was determined that an Apache server is running on a Linux Alma, and the version of the Apache server was detected as 2.4.53

![image](https://github.com/user-attachments/assets/415156b0-aa21-4adc-a8d3-2da2d4aa1e14)


### Task 3 - Scan Detected Hosts for Vulnerabilities with OWASP ZAP

In the task, the OWASP ZAP application will be used to scan the detected hosts for vulnerabilities.

First, open the zap in the Web Applications Analysis menu in Kali, then scanned the intened web server fo rvulnerabilitie

![image](https://github.com/user-attachments/assets/63fabf78-e4ec-44ec-8610-95aea8af76eb)

In the Absence of Anti-CSRF Tokens, a vulnerable web application has been implemented on the ACIM01 device which is Windows server 2022

![image](https://github.com/user-attachments/assets/4163ca9b-c9ec-4159-b7d5-ac2375be4fae)


### Task 4 - Scan Detected Hosts for Vulnerabilities with Metasploit and Nmap

The Metasploit Framework application can be used in conjunction with the nmap application to detect web application vulnerabilities.

In this task, the Metasploit Framework application will be used to detect web application vulnerabilities.

![image](https://github.com/user-attachments/assets/286519b4-c9ae-48d0-a7f3-d1603f9342ac)

![image](https://github.com/user-attachments/assets/0373a2d0-94b0-4ad9-b2b8-7f5f85c43c96)

The range of the open ports that will be scanned can be adjusted according to the needs of the assessment.
The metasploitable application was used to test which ports are open on the detected host. From the results, it can be seen that Port 9000 is open.

![image](https://github.com/user-attachments/assets/9c6e36a6-f984-40e2-b7c2-a58c93511898)

The nmap application was used to determine the version and the operating system hosting the Apache Server.





