# azure-honeypot-with-attack-map

<img width="360" height="177" alt="Image" src="https://github.com/user-attachments/assets/410471d8-00d8-47c9-bc79-176fc810ec07" />

Overview
...

# Instructions 

Setup Azure Subscription

Create Free Azure Subscription: https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account

If Azure doesn’t let you create a free account, you can either
Create a paid subscription and be mindful of shutting down/deleting your resources when you are done.

After your subscription is created, you can login at:
https://portal.azure.com


# Create the Honey Pot (Azure Virtual Machine)

1. Go to: https://portal.azure.com and search for virtual machines

2. Create a new Windows 10 virtual machine (choose an appropriate size so that you can smoothly navigate your VM). 

3. Choose the Standard E2s v3 (2 vcpus, 16 GiB memory)

4. Go to the Network Security Group for your virtual machine and create a rule that allows all traffic inbound. Disregard the warnings.

5. Log into your virtual machine and turn off the windows firewall (start -> wf.msc -> properties -> all off) you can use RDP if on windows. However, on Mac you will need to download the “Windows App”. You will need to add your VM’s Public IP when selecting Add PC in the Windows App.


<img width="356" height="410" alt="Image" src="https://github.com/user-attachments/assets/58c16df2-aefa-48fd-8d8a-122c5ded5b81" />
<img width="498" height="133" alt="Image" src="https://github.com/user-attachments/assets/90d8b9bc-8f07-42fe-86f2-f3a7d028534a" />




6. Next we will log into our VM and then turn off the firewall by searching for windows defender and selecting turn off firewall. Then Log out of the VM.

<img width="500" height="241" alt="Image" src="https://github.com/user-attachments/assets/56737ffe-7337-4a27-97dd-fb3d8fae3877" />


# Logging into the VM and inspecting logs

1. Fail 3 logins as some other username
2. Login to your virtual machine
3. Open up “Event Viewer” by searching for “Event Viewer” and inspect the security logs
4. Select “Windows Logs” on the left panel then Select “Find” on the right panel
5. Search for 4625
6. See the 3 failed logins as “<Failed Login User>”, event ID 4625
7. Next, we are going to create a central log repository called a LAW

<img width="504" height="241" alt="Image" src="https://github.com/user-attachments/assets/d7bfb4d9-4640-4c29-98c9-45b8a68d085f" />


# Log Forwarding and KQL

Create Log Analytics Workspace by searching “Log Analytics Workspace”
Create a Sentinel Instance and connect it to Log Analytics
Configure the “Windows Security Events via AMA” connector.

<img width="503" height="228" alt="Image" src="https://github.com/user-attachments/assets/a20ec640-ee05-4f10-84f0-4dbef16140cf" />


Create the DCR within sentinel, watch for extension creation.
Query for logs within the LAW.
We can now query the Log analytics workspace as well as the SIEM, sentinel directly, which we will do soon.



Observe some of your VM logs:

SecurityEvent
| where EventId == 4625





# Log Enrichment and Finding Location Data

Observe the SecurityEvent logs in the Log Analytics Workspace; there is no location data, only IP address, which we can use to derive the location data.

<img width="503" height="466" alt="Image" src="https://github.com/user-attachments/assets/13b8fddd-e84d-4f1e-8bf2-f7b7311c9985" />


goto what is my ip address to review highlighted attacker ip information

<img width="493" height="425" alt="Image" src="https://github.com/user-attachments/assets/60f293f2-3d4b-444f-8c08-2aad39c89df7" />


We are going to import a spreadsheet (as a “Sentinel Watchlist”) which contains geographic information for each block of IP addresses.

# Download: geoip-summarized.csv 

Within Sentinel, create the watchlist:

Name/Alias: geoip
Source type: Local File
Number of lines before row: 0
Search Key: network

Allow the watchlist to fully import, there should be a total of roughly 54,000 rows.

In real life, this location data would come from a live source or it would be updated automatically on the back end by your service provider.

Observe the logs now have geographic information, so you can see where the attacks are coming from

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents



# Attack Map Creation

1. Within Sentinel, create a new Workbook

2. Delete the prepopulated elements and add a “Query” element

3. Go to the advanced editor tab, and paste the JSON

{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}

I would recommend waiting anywhere from 12 to 24 horse so that your VM can have malicious traffic flow to it. This will produce additional points of interest on your attack map.

<img width="360" height="177" alt="Image" src="https://github.com/user-attachments/assets/410471d8-00d8-47c9-bc79-176fc810ec07" />







