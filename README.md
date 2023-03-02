# SentryWire_xSOAR

# Configure SentryWire on Cortex xSOAR
1. Navigate to **Settings** > **Integrations**

2. Search for SentryWire

3. Click add an instance and configure

| Parameter    | Description                    | Required |
|--------------|--------------------------------|----------|
| Name         | Identifier for instance        | True     |
| Unit Address | ip/hostname of SentryWire unit | True     |
| Username     |                                | True     |
| Password     |                                | True     |

4. ~~Click **Test** to validate connectivity to SentryWire unit~~

# Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

## sentrywire-login
___

Authorize the current instance with an authentication token distributed by the SentryWire unit
### Base Command
```
sentrywire-login
```
### Input
N/A
### Context Output
| Key       | Description           |
|-----------|-----------------------|
| auth_type | login/logout          |
| expires   | Token expiration date | 
| issued    | Token issue date      |
| username  |                       |
### Command Example
```
!sentrywire-login
```
### Context Example
```
{
     "SentryWire": {
        "Authentication": {
            "auth_type": "login",
            "expires": "2023-01-02 06:00:00",
            "issued": "2023-01-01 22:00:00",
            "username": "example"
        }
    }
}
```
### Human Readable Output
```
Logged in!
```

## sentrywire-logout
___

Deauthorize the current instance and clear cached token
### Base Command
```
sentrywire-logout
```
### Input
N/A
### Context Output
| Key       | Description  |
|-----------|--------------|
| auth_type | login/logout |
| username  |              |
### Command Example
```
!sentrywire-logout
```
### Context Example
```
{
     "SentryWire": {
        "Authentication": {
            "auth_type": "logout",
            "username": "example_account"
        }
    }
}
```
### Human Readable Output
```
Logged out!
```

## sentrywire-create-search
___

Create a search on the SentryWire unit
### Base Command
```
sentrywire-create-search
```
### Input
| Argument      | Description                                                                                                                        | Required |
|---------------|------------------------------------------------------------------------------------------------------------------------------------|----------|
| search_name   |                                                                                                                                    | True     |
| search_filter | KQL Search Filter                                                                                                                  | True     |
| begin_time    | UTC time - YYYY-MM-DD hh:mm:ss                                                                                                     | True     |
| end_time      | UTC time - YYYY-MM-DD hh:mm:ss                                                                                                     | True     |
| max_packets   | Default: 0 => get all packets                                                                                                      | False    |
| targetlist    | Controls the list of federated nodes this request is sent to. Default: send the request to all federated nodes monitored by the FM | False    |
### Context Output
| key         | Description                                                      |
|-------------|------------------------------------------------------------------|
| search_id   | Unique ID that can be used to reference search in other commands |
| checkstatus | Link to check the status of a search                             |
| getpcaps    | Link to the PCAP files ascociated with the search                |
| metadata    | Link to the metadata ascociated with the search                  |
### Command Example
```
!sentrywire-create-search search_name="example_search" search_filter="http.client.os.name: windows AND dest_port: 8080" begin_time="2023-01-01 01:00:00" end_time="2023-01-02 01:00:00" max_packets="100"
```
### Context Example
```
{
    "SentryWire":{
        "Search": {
            "History": {
                "checkstatus": "https://1.2.3.4:41395/v3/fnsearchstatus?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1",
                "getpcaps": "https://1.2.3.4:41395/v3/fnpcaps?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1",
                "metadata": "https://1.2.3.4:41395/v3/fnmetadata?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1",
                "search_id": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
### Human Readable Output
|             |                                                                                                                                                                 |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------| 
| search_id   | example_account_1675209608_43_example_search                                                                                                                    |
| checkstatus | https://1.2.3.4:41395/v3/fnsearchstatus?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1  |
| getpcaps    | https://1.2.3.4:41395/v3/fnpcaps?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1         |
| metadata    | https://1.2.3.4:41395/v3/fnmetadata?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1      |
## sentrywire-delete-search
___

Delete a previously run search from the SentryWire unit.
### Base Command
```
sentrywire-delete-search
```
### Input
| Argument  | Description                                           | Required |
|-----------|-------------------------------------------------------|----------|
| search_id | ID provided by the "sentrywire-create-search" command | True     |
### Context Output
| Key       | Description     |
|-----------|-----------------|
| message   | Server response |
| search_id |                 |
### Command Example
```
!sentrywire-delete-search search_id="example_account_1675209608_43_example_search"
```
### Context Example
```
{
    "SentryWire":{
        "Search": {
            "Deleted": {
                "message": "deleted search example_account_1675209608_43_example_search",
                "search_id": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
### Human Readable Output
```
example_account_1675209608_43_example_search has been deleted!
```
## sentrywire-get-pcap

___

Download the pcap file of a search from the SentryWire unit
### Base Command
```
sentrywire-get-pcap
```
### Input
| Argument | Description                                     | Required |
|----------|-------------------------------------------------|----------|
| url      | provided the "sentrywire-create-search" command | True     |
### Context Output
| Key       | Description |
|-----------|-------------|
| EntryID   |             |
| Extension |             |
| Info      |             |
| MD5       |             |
| Name      |             |
| SHA1      |             |
| SHA256    |             |
| SHA512    |             |
| SSDeep    |             |
| Size      |             |
| Type      |             |
### Command Example
```
!sentrywire-get-pcap url="https://1.2.3.4:41395/v3/fnpcaps?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1"
```
### Context Example
```
"File": {
    "EntryID": "123@456789ab-1234-cdef-5678-9ghijklmnopq",
    "Extension": "pcap",
    "Info": "application/vnd.tcpdump.pcap",
    "MD5": "e777ee76980a9e912d6464ff8bd31d06",
    "Name": "example_account_1675209608_43_example_search.pcap",
    "SHA1": "8ee5665baa5efed45293925f30aa9dafe42c916c",
    "SHA256": "59b55d37dfc0ae946238ab98aa040ab825da6d4d6b305a2cf0749f7423a102c4",
    "SHA512": "379a7696aebebc1974288ad980ec7913a9142d7a2bb630daf1f999c9c5bb24fbdd4a03047a9f6f1b69551a16deefc0f8e0395aeeaa80f9616fe9ba872ca3e8d3",
    "SSDeep": "98304:WHX0aNGsTD0ucYps10Sm+4Pz/BPrjN2h15CpzVc+:W30aM0DYys10D++zlx2h15CpzT",
    "Size": 4416449,
    "Type": "data"
}
```
### Human Readable Output
```
Uploaded file: example_account_1675209608_43_example_search.pcap
```
## sentrywire-get-metadata

___

Download the metadata of a search from the SentryWire unit
### Base Command
```
sentrywire-get-metadata
```
### Input
| Argument | Description                                     | Required |
|----------|-------------------------------------------------|----------|
| url      | provided the "sentrywire-create-search" command | True     |
### Context Output
| Key       | Description |
|-----------|-------------|
| EntryID   |             |
| Extension |             |
| Info      |             |
| MD5       |             |
| Name      |             |
| SHA1      |             |
| SHA256    |             |
| SHA512    |             |
| SSDeep    |             |
| Size      |             |
| Type      |             |
### Command Example
```
!sentrywire-get-metadata url="https://1.2.3.4:41395/v3/fnmetadata?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1"
```
### Context Example
```
"File": {
    "EntryID": "319@f51e3938-4446-47c4-8ced-92e7d1c02f38",
    "Extension": "zip",
    "Info": "application/zip",
    "MD5": "f9377771fe08464836db0005510ef999",
    "Name": "example_account_1675209608_43_example_search.zip",
    "SHA1": "7c85e6e36ded690a2ce72c286cd8654dbe6067fc",
    "SHA256": "59381cd490adc746b094bbc64f69ae4bd1badb355c6ade3932dd809e8b8d2e95",
    "SHA512": "1d7ce714f017481bb0be27563280772d51d3239d16c6fc74ef86808ed20ca4553a306e643557afefb0f2a73a95467054d33f6a895be8996c4383a03e5c70b5bc",
    "SSDeep": "3072:nIyYR65VdV3faJsTk0aWJ5WT4BGEbX58OQsJxbPfk2PPcYJE3nR0eXHNcR19:ndJBfRQ0n5D5wQFPflUYeR0e3WZ",
    "Size": 202477,
    "Type": "Zip archive data, at least v2.0 to extract"
}
```
### Human Readable Output
```
Uploaded file: example_account_1675209608_43_example_search.zip
```
## sentrywire-get-search-status

___

Get detailed information about a search conducted on the SentryWire unit
### Base Command
```
sentrywire-get-search-status
```
### Input
| Argument | Description                                     | Required |
|----------|-------------------------------------------------|----------|
| url      | provided the "sentrywire-create-search" command | True     |
### Context Output
| Key            | Description |
|----------------|-------------|
| Begintime      | x           |
| CaseName       | x           |
| Endtime        | x           |
| ID             | x           |
| MasterToken    | x           |
| MaxChunk       | x           |
| MaxPacketCount | x           |
| NodeName       | x           |
| SearchFilter   | x           |
| SearchKey      | x           |
| SearchName     | x           |
| SearchPorts    | x           |
| SearchResult   | x           |
| SearchStatus   | x           |
| SearchType     | x           |
| SubmittedTime  | x           |
| search_id      | x           |

### Command Example
```
!sentrywire-get-search-status url="https://1.2.3.4:41395/v3/fnsearchstatus?rest_token=abcdefgh-1234-ijkl-5678-mnopqrstuvwx&searchname=example_account_1675209608_43_example_search&nodename=ncvm1"
```
### Context Example
Pending
```
{
    "SentryWire": {
        "Search": {
            "Status": {
                "Begintime": "2023-01-01 01:00:00",
                "CaseName": "example_account_1675209608_43_example_search",
                "Endtime": "2023-01-02 01:00:00",
                "ID": "63d9ab9dafe7047fc06188a6",
                "MasterToken": "",
                "MaxChunk": "1",
                "MaxPacketCount": "100",
                "NodeName": "ncvm1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchKey": "example_account_1675209608_43_example_searchncvm1",
                "SearchName": "example_account_1675209608_43_example_search",
                "SearchPorts": "",
                "SearchResult": "Pkts=114 Seconds=4 TotalSize=15KB",
                "SearchStatus": "Pending",
                "SearchType": "",
                "SubmittedTime": "1675209618532",
                "search_id": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
Completed
```
{
    "SentryWire": {
        "Search": {
            "Status": {
                "Begintime": "2023-02-06 07:00:00",
                "CaseName": "example_account_1675209608_43_example_search",
                "Endtime": "2023-02-07 10:00:00",
                "ID": "63e2c09943bdb43b7ba61a41",
                "MasterToken": "",
                "MaxChunk": "1",
                "MaxPacketCount": "100",
                "NodeName": "ncvm1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchKey": "example_account_1675209608_43_example_searchncvm1",
                "SearchName": "example_account_1675209608_43_example_search",
                "SearchPorts": "",
                "SearchResult": "Pkts=114 Seconds=4 TotalSize=15KB",
                "SearchType": "",
                "SubmittedTime": "1675804817300",
                "search_id": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
Cancelled
```
{
    "SentryWire": {
        "Search": {
            "Status": {
                "Begintime": "2023-02-06 07:00:00",
                "CaseName": "example_account_1675209608_43_example_search",
                "Endtime": "2023-02-07 10:00:00",
                "ID": "63e2c044b2da4ffc9561315d",
                "MasterToken": "",
                "MaxChunk": "",
                "MaxPacketCount": "",
                "NodeName": "ncvm1",
                "SearchFilter": "http.client.os.name: windows AND dest_port: 8080",
                "SearchKey": "example_account_1675209608_43_example_searchncvm1",
                "SearchName": "example_account_1675209608_43_example_search",
                "SearchPorts": "",
                "SearchResult": "Cancelled",
                "SearchStatus": "Pending",
                "SearchType": "",
                "SubmittedTime": "1675804691",
                "search_id": "example_account_1675209608_43_example_search"
            }
        }
    }
}
```
### Human Readable Output
Pending
```
Search status: Pending
```
Completed
```
Search completed: Pkts=114 Seconds=4 TotalSize=15KB
```
Cancelled
```
Search completed: Cancelled
```
## sentrywire-get-object-list

___

Download a list of the object data ascociated with a search
### Base Command
```
sentrywire-get-object-list
```
### Input
| Argument  | Description | Required |
|-----------|-------------|----------|
| search_id |             | True     |
| node_name |             | True     |
### Context Output
| Key       | Description |
|-----------|-------------|
| EntryID   |             |
| Extension |             |
| Info      |             |
| MD5       |             |
| Name      |             |
| SHA1      |             |
| SHA256    |             |
| SHA512    |             |
| SSDeep    |             |
| Size      |             |
| Type      |             |
### Command Example
```
!sentrywire-get-object-list search_id=example_account_1675209608_43_example_search node_name=ncvm1
```
### Context Example
```
{
    "":""
}
```
### Human Readable Output

## sentrywire-get-object-data

___

Download a the object data ascociated with a search **CAUTION: Files may be malicous!**
### Base Command
```
sentrywire-get-object-data
```
### Input
| Argument  | Description | Required |
|-----------|-------------|----------|
| search_id |             | True     |
| node_name |             | True     |
### Context Output
| Key       | Description |
|-----------|-------------|
| EntryID   |             |
| Extension |             |
| Info      |             |
| MD5       |             |
| Name      |             |
| SHA1      |             |
| SHA256    |             |
| SHA512    |             |
| SSDeep    |             |
| Size      |             |
| Type      |             |
### Command Example
```
!sentrywire-get-object-data search_id=example_account_1675209608_43_example_search node_name=ncvm1
```
### Context Example
```
{
    "":""
}
```
### Human Readable Output
