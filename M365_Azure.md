## UAL Records
Workload: Application that generated the log entry
	AttractiveDirectory
	SharePoint
	MicrosoftTeams
	OneDrive
	Exchange 
	Security Compliance Centre
Record Types (record_type): Logical group of operations
Operations: Specific action being taken for the event that's being recorded
## Entra ID
AzureActiveDirectoryStsLogon (Record type 15): Entra ID audit logs that captures Secure Token Service (STS) log on events, related to user authentication activity within the organization. Also records login activity from security principals.
	useragent
	useragentinfo.name
AzureActiveDirectory (Record type 8): Records everything at the tenant level
	modified_properties.DelegatedPermissionGrant.Scope.NewValue/OldValue
	modified_properties.AppAddress.NewValue/OldValue
**Operation**
	UserLoggedIn
	UserLoginFailed
		LogonError:
			ConditionalAccessFailed
			InvalidUserNameOrPassword
			UserStrongAuthEnrollmentRequiredInterrupt
	Add user
	Add service principal
	Consent to application
	Remove delegated permission grant 
	Update device
UserId
user_name
ClientIP
ActorIPAddress
Client: Has details about the client device, operating system, and browser
ApplicationId: The unique identifier (GUID) of the application requesting the sign in.
DeviceProperties: Has information about the device involved in the sign-in including details like the device ID, display name, operating system, browser, compliance status, and a session ID.
ErrorCode
ResultStatus
authentication_details.authenticationStepResultDetail

## Entra ID Log: User Login (example)
```
@timestamp: 2020-04-11 17:55:29.000 +00:00
workload: AzureActiveDirectory
operation: UserLoggedIn
client ip: 104.238.59.218
user ids: dcross@pymtechlabs.com
useragent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36
```

## Entra ID Log: System-Generated Event (example)
```
@timestamp: 2020-04-11 17:40:37.000 +00:00
workload: AzureActiveDirectory
object_id: dcross@pymtechlabs.com
operation: Add member to group.
client ip: 40.126.6.52
modified_properties:
  "Name": "AccountEnabled",
  "OldValue": "[]",
  "NewValue": "[\r\n  true\r\n]"
result_status: Failure
user_ids: ServicePrincipal_87b15a38-add8-47ec-aaff-0a98e8b42edb
```
## Exchange
**Record Type**
ExchangeItemAggregated (Record type 50): Captures aggregated Exchange mailbox operations that involve repetitive activities occurring within a short duration. Designed to log bulk actions performing on multiple mailbox items like moving or to leading numerous emails simultaneously.
ExchangeAdmin (Record type 1)
ExchangeItem (Record type 2):
**Operation**
	Create
	Send
	Set-Mailbox
	Add-MailboxPermission
	Set-OwaMailboxPolicy
	Set Company Information
Other Fields:
	LogonType: Owner, Delegate, Admin
	Action: 
		MailItemsAccessed: Mail data is accessed by mail protocols and clients. Provides detailed information about message activity.
			CreationTime: UTC
			RecordType: 2 (ExchangeItem) or 50 (ExchangeItemAggregated)
			ClientIpAddress: IP address of the client that made the request
			AppId: GUID of the app accessing the mailbox (important when using Graph API)
			UserId: User Principal Name who authorized the action
			ClientInfoString: Type of mail client used to access the mailbox
				"Client=MSExchangeRPC", MailAccessType: Sync. Classic Outlook
				"Client=REST", MailAccessType: Bind. New Outlook
				"Client=OWA", MailAccessType: Bind
				"Client=POP3/IMAP4", MailAccessType: Bind. Thunderbird and other mail clients
				"Client=OutlookService;Outlook-Android/2.0", MailAccessType: Bind
				"Client=OutlookService;Outlook-iOS/2.0", MailAccessType: Bind
				"Client=ActiveSync", MailAccessType: Sync. Older mobile devices
			MailboxOwnerUPN: Which mailbox being accessed?
			OperationProperties/MailAccessType: Bind or Sync
			OperationProperties/IsThrottled: True or False
			Folders: Contains InternetMessageId (unique ID) for each message access if access type is Bind. If the access type is Sync, it will contain the name of the folder that's being synced.
				folders.Path
		MoveToDeletedItems: A message was deleted and moved to the Deleted Items folder
		SoftDelete: A message was permanently deleted or deleted from the folder Deleted Items. Soft deleted items are moved to the Recoverable Items folder.
		HardDelete: A message was purged from the folder Recoverable Items.
		Update: A message or its properties were changed.
		UpdateCalendarDelegation: Gives someone else in the same organization permissions to manage the mailbox owner's calendar.
		UpdateFolderPermissions
		UpdateInboxRules
Other Fields:  
	UserId
	ClientIp
	ClientInfoString
	AffectedItems
	parameters.ForwardingSmtpAddress
	parameters.DeliverToMailboxAndForward
	organization_name
	item.Subject: Email subject line
	object_id: Full path and file name, ie "https://pymtechlabs-my.sharepoint.com/personal/admin_pymtechlabs_com/Documents/ProjectQuantumNextGen/QuantumNextGenMachine.pdf"

## New Outlook Bind Log Event (example)
```
"CreationTime": "2024-05-18T20:30:56",
"Operation": "MailItemsAccessed",
"RecordType": "50",
"Workload": "Exchange",
"UserId": "pierre@pymtechlabs.com",
"AppId": "13937bba-652e-4c46-b222-3003f4d1ff97",
"ClientIPAddress": "2603:10b6:806:141::21",
"ClientInfoString": "Client=REST;Client=RESTSystem;;",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": {
    "Name": "MailAccessType",
    "Value": "Bind", }
"Folders": {
    "InternetMessageId": "<WI9BBGSA1NU4.EHUGWNFoO3H11@ds3pepf00001e4d>",
    "InternetMessageId": "<GKUFF17VUMU4.F5IZAG3FCKQU3@ds3pepf00001e4e>" }
```

# Classic Outlook Sync Log Event
```
"CreationTime": "2024-05-18T22:30:06",
"Operation": "MailItemsAccessed",
"RecordType": "2",
"Workload": "Exchange",
"UserId": "pierre@pymtechlabs.com",
"AppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
"ClientIPAddress": "104.238.59.218",
"ClientInfoString": "Client=MSExchangeRPC",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": {
    "Name": "MailAccessType",
    "Value": "Sync" },
"Item": {
    "ParentFolder": {
        "Name": "Inbox" }
```

## New Outlook Log Entry (example)
```
"CreationTime": "2024-05-18T20:52:23",
"Id": "154da9a3-19cf-475f-bb47-db04f7192afc",
"Operation": "MailItemsAccessed",
"OrganizationId": "7e325eda-7945-46d3-ac99-f0dcfeb4628e",
"RecordType": 50,
"ResultStatus": "Succeeded",
"UserKey": "1003200363F073B",
"UserType": 0,
"Version": 1,
"Workload": "Exchange",
"UserId": "pierre@pymtechlabs.com",
"AppId": "5d661950-3475-41cd-a2c3-d671a3162bc1",
"ClientIPAddress": "66.33.105.218",
"ClientInfoString": "Client=OWA;Action=ViaProxy",
"ExternalAccess": false,
"InternalLogonType": 0,
"LogonType": 0,
"LogonUserSid": "S-1-5-21-4077631301-2250677143-2330469894-53071535",
"MailboxGuid": "0e798c33-3019-419b-a4d1-c482d2b34636",
"MailboxOwnerSid": "S-1-5-21-4077631301-2250677143-2330469894-53071535",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": [{
    "Name": "MailAccessType",
    "Value": "Bind"
}, {
    "Name": "IsThrottled",
    "Value": "False"
}]
"OrganizationName": "pymtechlabs.onmicrosoft.com",
"OriginatingServer": "SA2PR06MB7369 (15.20.4200.000)",
"SessionId": "92ec6dd7-be57-4063-b9fc-8015ecef0347",
"Folders": [{
    "FolderItems": [{
        "Id": "RgAAAAD2IPIHi+5hRbpG6a+Y0KnMBwDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAADP0tqHm zKnRYIeTca3RkfiAAAAAixKAAA",
        "InternetMessageId": "<1159ce67-1e05-4f0c-908c-531e36032453@az.northcentralus.microsoft.com>",
        "SizeInBytes": 153806
    }, {
        "Id": "RgAAAAD2IPIHi+5hRbpG6a+Y0KnMBwDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAADP0tqHm zKnRYIeTca3RkfiAAAAIxJAAJ",
        "InternetMessageId": "<33c8d10-fd9b-435f-9a33-e62832edc462@CO1NAM11BG403.eop-nam11.prod.protection.outlook.com>",
        "SizeInBytes": 49753
    }, {
        "Id": "RgAAAAD2IPIHi+5hRbpG6a+Y0KnMBwDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAADP0tqHm zKnRYIeTca3RkfiAAAG+et8AAA",
        "InternetMessageId": "<TCL29ARHTMU4.VMQRU794IGU1@lb6pepf0000b4b8>",
        "SizeInBytes": 143498
    }, {
        "Id": "RgAAAAD2IPIHi+5hRbpG6a+Y0KnMBwDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAADP0tqHm zKnRYIeTca3RkfiAAAAIw4AAA",
        "InternetMessageId": "<034d4583-27ff-4b78-980a-b1f687d8b045@az.westus.microsoft.com>",
        "SizeInBytes": 147963
    }, {
        "Id": "RgAAAAD2IPIHi+5hRbpG6a+Y0KnMBwDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAADP0tqHm zKnRYIeTca3RkfiAAAG+et6AAA",
        "InternetMessageId": "<03c3684f-5e6c-4605-8726-145ee2c75254@az.northcentralus.microsoft.com>",
        "SizeInBytes": 154138
    }]
}, {
    "Id": "LgAAAAD2IPIHi+5hRbpG6a+Y0KnMAQDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAAB",
    "Path": "\\Inbox"
}],
"OperationCount": 5
```

## OWA Bind Log Event (example)
```
"CreationTime": "2024-05-18T20:52:23",
"Operation": "MailItemsAccessed",
"RecordType": "50",
"Workload": "Exchange",
"UserId": "pierre@pymtechlabs.com",
"AppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
"ClientIPAddress": "104.238.59.218",
"ClientInfoString": "Client=OWA;Action=ViaProxy",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": {
    "Name": "MailAccessType",
    "Value": "Bind"
},
"Folders": {
    "InternetMessageId": "<TCL29ARHTMU4.VMQRU794IGU1@lb6pepf0000b4b8>"
}
```

## POP3/IMAP4 Bind Log Event (example)
```
"CreationTime": "2024-05-18T21:56:22",
"Operation": "MailItemsAccessed",
"RecordType": "50",
"Workload": "Exchange",
"UserId": "pierre@pymtechlabs.com",
"ClientIPAddress": "104.238.59.218",
"ClientInfoString": "Client=POP3/IMAP4;Protocol=IMAP4",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": {
    "Name": "MailAccessType",
    "Value": "Bind" },
"Folders": {
    "InternetMessageId": "<S628L30G3NU4.51HLO5MYHKS8@cy4pepf00005d0o>",
    "InternetMessageId": "<TCL29ARHTMU4.VMQRU794IGU1@lb6pepf0000b4b8>" }
```
## SharePoint
SharePointFileOperation (Record type 6 and 36):
	FilePreviewed: high volume, noisy operation generated e.g. from viewing an image gallery, and can occur even if a user never accesses a file simply because a folder contains that file.
	PageViewed
	FileDownloaded
	FileAccessed
	FileCopied
	FileDeleted
	FileRecycled
	FileDeletedFirstStageRecycle: shows when the recycle bin is emptied
	FileDownloaded
	FileModified
	FileSyncUploadedFull
	FileSyncDownloadedFull
	FileRenamed
	FileRestored
	FolderCreated
	ListUpdated: User updates a SharePoint list by modifying one and more properties.
	ListViewed
	FileAccessedExtended: logged when the same person continually accesses a file for up to three hours.
	FullModifiedExtended: logged when the same person continually modifies a file for up to three hours.
SharePointListOperation:
	ListViewed
SharePointSharingOperation (Record type 14):
	AddedToGroup
	AnonymousLinkCreated
	SharedLinkCreated
	SharedLinkDisabled
	SharingRevoked
	SharingSet
	SharingInvitationAccepted
	SecureLinkCreated
Other fields:
	source_filename

## One Drive
OneDrive (record type 36)

## Virtual Machine Types
Series A: Entry Level
	Example: A1 v, A2 v2
Series B: Burstable
	Example: B1S, B2S, B4MS
Series D: General Purpose
	Example: D2a v4, D2as v4, D2d v4
Series F: Compute Optimized - have a high CPU to memory ratio
	Example: F1, F1s, F2s v2
Series E, G, and M: Memory Optimized - ideal for memory intensive applications like database servers
	Example: E2a v4, E2as v4, E2ds v4
Series L: Storage Optimized - NVMe storage
	 Example: L8s v2, L4s
Series NC, NV, ND: Graphics Optimized - targets applications like visualization, deep learning, predictive analytics
	Example: NC6, NC6s v2, NC4as T4
Series H: High Performance Computing
## File Operation Log (example)
| Timestamp               | Workload   | Record | Operation      | Source Filename                  |
| ----------------------- | ---------- | ------ | -------------- | -------------------------------- |
| 2023-04-22 16:29:50.000 | OneDrive   | 6      | FileRenamed    | Quantum Anomalies.pdf            |
| 2023-04-21 22:25:34.000 | SharePoint | 6      | FileRecycled   | Rescue Plan.doc                  |
| 2023-04-21 22:25:27.000 | SharePoint | 6      | FileDownloaded | Rescue Plan.doc                  |
| 2023-04-21 22:24:26.000 | OneDrive   | 6      | FileRecycled   | Quantum Travel.pdf               |
| 2023-04-21 16:09:36.000 | OneDrive   | 6      | FilePreviewed  | File-OneDriveDesktop.docx        |
| 2023-04-21 16:09:36.000 | SharePoint | 6      | FilePreviewed  | Quantum Tunnel Calculations.xlsx |
| 2023-04-21 16:09:36.000 | OneDrive   | 6      | FilePreviewed  | File-SharePointWeb.docx          |

## File Sharing Log: Anyone (example)
| Timestamp               | Workload | Record | Operation            | Source Filename                    | Event Data                                                      |
| ----------------------- | -------- | ------ | -------------------- | ---------------------------------- | --------------------------------------------------------------- |
| 2023-04-21 00:53:03.000 | OneDrive | 14     | AnonymousLinkCreated | Path through the Quantum Realm.pdf | `<Type>Edit</Type>`                                             |
| 2023-04-21 00:53:03.000 | OneDrive | 14     | SharingSet           | Path through the Quantum Realm.pdf | `<Permissions granted>Limited Access</Permissions granted>`     |
| 2023-04-21 00:53:03.000 | OneDrive | 14     | SharingSet           | Path through the Quantum Realm.pdf | `<Permissions granted>Contribute</Permissions granted>`         |
| 2023-04-21 00:53:03.000 | OneDrive | 14     | SharingSet           | Path through the Quantum Realm.pdf | `<Permissions granted>System.LimitedEdit</Permissions granted>` |
| 2023-04-21 00:53:30.000 | OneDrive | 14     | AnonymousLinkRemoved | Path through the Quantum Realm.pdf | `<Type>Edit</Type>`                                             |

## File Sharing Log:  Secure
| Timestamp               | Workload | Record | Operation                | Source Filename            | Event Data                               |
| ----------------------- | -------- | ------ | ------------------------ | -------------------------- | ---------------------------------------- |
| 2023-04-21 22:18:36.000 | OneDrive | 14     | AddedToGroup             | -                          | `<Group>SharingLinks...`                 |
| 2023-04-21 22:18:36.000 | OneDrive | 14     | AddedToSecureLink        | Quantum Realm Analysis.pdf | `<Type>View</Type>`                      |
| 2023-04-21 22:18:36.000 | OneDrive | 14     | SharingInheritanceBroken | Quantum Realm Analysis.pdf | `<ClearSubScopes>False</ClearSubScopes>` |
| 2023-04-21 22:18:36.000 | OneDrive | 14     | SecureLinkCreated        | Quantum Realm Analysis.pdf | `<Type>View</Type>`                      |

## File Lifecycle (example)
| Timestamp               | Workload | Record | Operation            | Source Filename                  |
| ----------------------- | -------- | ------ | -------------------- | -------------------------------- |
| 2023-04-23 18:15:29.000 | OneDrive | 6      | FileSyncUploadedFull | New Microsoft Word Document.docx |
| 2023-04-23 18:15:46.000 | OneDrive | 6      | FileRenamed          | New Microsoft Word Document.docx |
| 2023-04-23 18:15:53.000 | OneDrive | 6      | FileAccessed         | Pymtechlabs Master Plan.docx     |
| 2023-04-23 18:16:26.000 | OneDrive | 6      | FileModified         | Pymtechlabs Master Plan.docx     |
| 2023-04-23 18:19:30.000 | OneDrive | 6      | FileAccessed         | Pymtechlabs Master Plan.docx     |
| 2023-04-23 18:20:00.000 | OneDrive | 6      | FileModifiedExtended | Pymtechlabs Master Plan.docx     |

## File Lifecycle with Sharing (example)
| Timestamp               | Workload | Record | Operation                | Source Filename              |
| ----------------------- | -------- | ------ | ------------------------ | ---------------------------- |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | SecureLinkCreated        | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | AddedToSecureLink        | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | SharingSet               | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:21:31.000 | OneDrive | 4      | GroupAdded               | -                            |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | SharingInheritanceBroken | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | AddedToGroup             | -                            |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | AddedToGroup             | -                            |
| 2023-04-23 18:21:31.000 | OneDrive | 14     | SharingSet               | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:21:35.000 | Exchange | 2      | Send                     | -                            |
## More File Lifecycle (example)

| Timestamp               | Workload | Record | Operation                       | Source Filename              |
| ----------------------- | -------- | ------ | ------------------------------- | ---------------------------- |
| 2023-04-23 18:24:03.000 | OneDrive | 6      | FileAccessed                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:03.000 | OneDrive | 14     | SecureLinkUsed                  | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:04.000 | OneDrive | 6      | FileAccessed                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:39.000 | OneDrive | 6      | FileModified                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:45.000 | OneDrive | 14     | SecureLinkUsed                  | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:49.000 | OneDrive | 6      | FileSyncDownloadedFull          | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:24:56.000 | OneDrive | 6      | FileDownloaded                  | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:25:18.000 | OneDrive | 6      | FileRecycled                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:26:05.000 | OneDrive | 6      | FileRestored                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:26:46.000 | OneDrive | 6      | FileRecycled                    | Pymtechlabs Master Plan.docx |
| 2023-04-23 18:26:58.000 | OneDrive | 6      | FileDeletedFirstStageRecycleBin | Pymtechlabs Master Plan.docx |
## Classic Outlook Sync Log Entry (example)
```
"CreationTime": "2024-05-18T22:30:06",
"Id": "696dcf61-c3b5-48d2-92eb-08dc778a11bd",
"Operation": "MailItemsAccessed",
"OrganizationId": "7e325eda-7945-46d3-ac99-f0dcfeb4628e",
"RecordType": 2,
"ResultStatus": "Succeeded",
"UserKey": "1003200363F073B",
"UserType": 0,
"Version": 1,
"Workload": "Exchange",
"ClientIP": "104.238.59.218",
"UserId": "pierre@pymtechlabs.com",
"AppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
"ClientIPAddress": "104.238.59.218",
"ClientInfoString": "Client=MSExchangeRPC",
"ClientProcessName": "OUTLOOK.EXE",
"ClientRequestId": "(27D01EB6-8C24-47BB-B8ED-D517EA4A8465)",
"ClientVersion": "16.0.17531.20004",
"ExternalAccess": false,
"InternalLogonType": 0,
"LogonType": 0,
"LogonUserSid": "S-1-5-21-4077631301-2250677143-2330469894-53071535",
"MailboxGuid": "0e798c33-3019-419b-a4d1-c482d2b34636",
"MailboxOwnerSid": "S-1-5-21-4077631301-2250677143-2330469894-53071535",
"MailboxOwnerUPN": "pierre@pymtechlabs.com",
"OperationProperties": [{
    "Name": "MailAccessType",
    "Value": "Sync"
}, {
    "Name": "IsThrottled",
    "Value": "False"
}],
"OrganizationName": "pymtechlabs.onmicrosoft.com",
"OriginatingServer": "SA2PR06MB7369 (15.20.4200.000)",
"SessionId": "92ec6dd7-be57-4063-b9fc-8015ecef0347",
"Item": {
    "Id": "LgAAAAD2IPIHi+5hRbpG6a+Y0KnMAQDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAAB",
    "ParentFolder": {
        "Id": "LgAAAAD2IPIHi+5hRbpG6a+Y0KnMAQDP0tqHmzKnRYIeTca3RkfiAAAAAAEMAAB",
        "Name": "Inbox",
        "Path": "Not Available"
    }
}
```
## GraphActivityLogs
AppId: GUID of the application making the request 
ServicePrincipalId: GUID of the service principal making the request
IpAddress: of the client making the request (mostly Microsoft IPs)
RequestUri: The specific API call being made
RequestMethod: Type of request, ie, GET POST PUT PATCH DELETE
	GET /users: List of users  
	POST /users: Create user  
	PATCH or PUT /users/{id | userPrincipalName}: Update user properties  
	DELETE /users/{id | userPrincipalName}: Delete user
Scopes: OAuth2.0 access token scopes (aka delegated permissions) granted to or requested by an app when accessing Graph. Examples incl --
	AuditLog.Read.All: Read all audit log data in your org (sign-in logs, directory audits, security events)
	Directory.AccessAsUser.All: Allows the app to access the directory as the signed-in user, ie it inherits the user’s directory permissions
	email: Grants the app access to the user’s primary email address
	Group.ReadWrite.All: Allows the app to read and write all groups, including group memberships
	openid: Required for OpenID Connect authentication flows; enables the app to identify the user
	profile: Grants access to basic user profile information such as name and tenant ID
	User.ReadWrite.All: Grants the app permission to read and write properties of all users in the directory
RequestStatusCode: Result of the request using HTTP codes, ie 200 for success
Roles/Scopes: Roles and scopes in the token claims that is presented to Graph API to make the request

Note that the Graph API endpoint (shown in RequestUri) is responsible for different accesses.

## Register App Logs (example)
| Timestamp                      | Operation                                                |
| ------------------------------ | -------------------------------------------------------- |
| 2021-06-07 22:25:36.686 +00:00 | Add service principal                                    |
| 2021-06-07 22:28:00.325 +00:00 | Add application                                          |
| 2021-06-07 22:28:00.375 +00:00 | Add owner to application                                 |
| 2021-06-07 22:28:00.813 +00:00 | Add service principal                                    |
| 2021-06-07 22:28:42.863 +00:00 | Update service principal                                 |
| 2021-06-07 22:28:42.953 +00:00 | Update application – Certificates and secrets management |
| 2021-06-07 22:28:42.958 +00:00 | Update application                                       |
| 2021-06-07 22:34:02.844 +00:00 | Update service principal                                 |
| 2021-06-07 22:34:02.899 +00:00 | Update application                                       |

## Register App Log: "Add Service Principal" (example)
```
time: 2021-06-07T22:28:00.8135635Z
resourceId: /tenants/7e325eda-7945-46d3-ac99-f0dcfeb4628e/providers/Microsoft.aadiam
operationName: Add service principal
targetResources: [
  {
    id: 208a6487-07da-48cb-a3a9-509c1fe05a14
    displayName: testapp
    type: ServicePrincipal
    modifiedProperties: [
      {
        displayName: AccountEnabled
        oldValue: []
        newValue: [true]
      },
      {
        displayName: AppPrincipalId
        oldValue: []
        newValue: ["30eala01-ef21-4000-93ea-0ed22c53ec7b"]
      }
    ]
  }
]
```

## Admin Approval Log Entry (example)

| Timestamp                      | Operation                                    |
| ------------------------------ | -------------------------------------------- |
| 2021-06-07 22:34:31.491 +00:00 | Add app role assignment to service principal |
| 2021-06-07 22:34:31.596 +00:00 | Add delegated permission grant               |
| 2021-06-07 22:34:31.661 +00:00 | Add app role assignment grant to user        |
| 2021-06-07 22:34:31.666 +00:00 | Consent to application                       |

## Adding a User Log Entry (Audit Log example)
```
creationtime: 2021-06-22T01:38:29
operation: Add user.
workload: AzureActiveDirectory
actor:
  ID: testapp
  ID: 30eala01-ef21-4000-93ea-0ed22c53ec7b
```

## Adding a User Log Entry 2 (Audit Log example)
```
modifiedProperties:
  displayName: AccountEnabled
    oldValue: []
    newValue: [true]
  displayName: DisplayName
    oldValue: []
    newValue: [Hydra]
  displayName: MailNickname
    oldValue: []
    newValue: [Hydra]
  displayName: UserPrincipalName
    oldValue: []
    newValue: [Hydra@pymtechlabs.com]
  displayName: UserType
    oldValue: []
    newValue: [Member]
```

## UAL Reading a Message Log Entry (example)
```
"CreationTime": "2021-06-24T18:42:29"
"Operation": "MailItemsAccessed"
"Workload": "Exchange"
"ClientAppId": "30eala01-ef21-4000-93ea-0ed22c53ec7b"
"ClientIPAddress": "20.190.157.30"
"ClientInfoString": "Client = REST; Client = RESTSystem"
"MailboxOwnerUPN": "JVanDyne@pymtechlabs.com"
"OperationProperties": {
    "Name": "MailAccessType",
    "Value": "Bind"
}
"Folders": {
    "Path": "\\ Inbox"
    "InternetMessageId": "<006101d76927$918ac230$b4a04690$@gmail.com>"
}
```
## Risky Permissions
BitlockerKey.Read.All
Chat.*
Directory.ReadWrite.All
eDiscovery.*
Files.*
MailboxSettings.ReadWrite
Mail.ReadWrite
Mail.Send
Sites.*
User.*
**Extremely Dangerous:**
AppRoleAssignment.ReadWrite.All
RoleManagement.ReadWrite.Directory

## Azure Sign-in Logs Fields
Time: DateTime in UTC
OperationName & Category: always set too "Sign in activity"  "SignIn"
ResultType: 0 for success, or an error code for failure
ResultDescription: may provide additional information regarding the reason
CallerIpAddress: of the client that made the request 
CorrelationId: GUID that can help correlate operations that span services. Best way to identify related services
User/<fields/>: Multiple fields showing the name of the user that authenticated. UserDisplayName, UserPrincipalName, UserId
AppId/AppDisplayName: The client used for the sign in
AuthenticationDetails: Multiple fields showing primary and secondary authentication methods

## Audit Log Fields
Time: DateTime in UTC
Category (aka property_category): Main category "AuditLogs", various secondary categories e.g. "DirectoryManagement", "UserManagement", "GroupManagement", "RoleManagement"
OperationName: Action being taken on that resource
	Update service principal
	Update application
	Update application - Certificates and secrets management: should be investigated!
		initiating_user_ip
		initiating_user_principal_name
		operation_type: such as Update
	Add app role assignment to service principal
		target_resource_modifications.SPN.newValue/oldValue
		target_resource.displayName
		target_resource_modifications.AppRole.Value.newValue/oldValue
			RoleManagement.ReadWrite.Directory
			User.ReadWrite.All
			Directory.ReadWrite.All
			AppRoleAssignment.ReadWrite.All: very powerful as it allows an app to grant permissions to another app (incl itself)!
	Add user
		target_resources.userPrincipalName: which user is being added?
	Add member to role: Important to investigate
		target_resources.userPrincipalName
		target_resource_modifications.Role.ObjectID.newValue/oldValue
		target_resource_modifications.Role.DisplayName.newValue/oldValue
		identity: who granted the role?
	Add app role assignment grant to user.
Add member to group
Add user
CallerIpAddress: of the client that made the request 
CorrelationId: GUID that can help correlate operations that span services. Best way to identify related services
InitiatedBy: UserPrincipalName that authorized the action
	app
		appId
		displayName
		servicePrincipalId
		servicePrincipalName
TargetResources_modifiedProperties: Details of changes being made
identity
operation_type: such as Assign

## Subscription/Activity Log Fields
Time: DateTime in UTC
Category: "Administrative" is the only one that we need for incident response
ResourceId: Resource being added, deleted, or modified
OperationName: Action being taken on that resource
	Deallocate Virtual Machine
	Create or Update Disk
	Validate Deployment
	Generate
	Update resource group: Create Resource Group, Crate VM, Shutdown VM
CallerIpAddress: of the client that made the request 
CorrelationId: GUID that can help correlate operations that span services. Best way to identify related services
UPN: User Principal Name that authorized the action
ResponseBody: A result of the operation

## VM Creation Events (with examples)
result_type
	Start, Except, Success
operation_name
	MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE
	MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE
	MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE
	MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE
	MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE
	MICROSOFT.NETWORK/VIRTUALNETWORKS/WRITE
	MICROSOFT.NETWORK/NETWORKWATCHERS/WRITE
	MICROSOFT.COMPUTE/DISKS/WRITE
response_body:
	name: “FlighPath”
	id: “/subscriptions//resourceGroups/WaspWing/providers/Microsoft.Compute/virtualMachines/FlighPath"
	vmSize: “Standard_L8s_v2”
	sku: “win11-22h2-pro”
	storageAccountType: “Premium_LRS”
	diskSizeGB: 127
	computerName: “FlighPath”
	adminUsername: “flightuser”

## NSG Rule Creation Log (example)
time: “2024-02-12T12:52:40.8698142Z”
resourceId: “/SUBSCRIPTIONS//RESOURCEGROUPS/LABRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/AADDS-NSG/SECURITYRULES/PORT_3389”
operationName: “MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE”
resultType: “Success”
resultSignature: “Succeeded”
callerIpAddress: “45.41.180.139”
correlationId: “efd98169-2530-43f2-a33c-c76805658ab9”
identity: {
	authorization: 
	claims: {
	“http://schemas.microsoft.com/claims/authnmethodsreferences”: “pwd,mfa”
	“http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn”: “admin@pymtechlabs.com”
	/<many additional fields not shown/>
}

## NSG Rule (example)
"requestbody": {
    "properties": {
        "description": "RDP port",
        "protocol": "*",
        "sourcePortRanges": null,
        "sourcePortRange": "*",
        "sourceAddressPrefix": "*",
        "destinationPortRanges": null,
        "destinationPortRange": "3389",
        "destinationAddressPrefix": "*",
        "access": "Allow",
        "priority": 100,
        "direction": "Inbound",
        "id": "/subscriptions/beb0c5fa-418f-4240-aa63-ff8cad3f1eb1/resourceGroups/labRG/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/securityRules/Port_3389",
        "name": "Port_3389"
    }
}

## NSG Logs (example)
"category": "NetworkSecurityGroupEvent",
"resourceId": "/SUBSCRIPTIONS/BEB0C5FA-418F-4240-AA63-FF8CAD3F1EB1/RESOURCEGROUPS/LABRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/AADDS-NSG",
"operationName": "NetworkSecurityGroupEvents",
"properties": {
    "vnetResourceGuid": "{7CD15BA6-B80F-40C4-BECF-BAD22571ED77}",
    "subnetPrefix": "10.1.0.0/24",
    "macAddress": "00-0D-3A-FC-A7-0B",
    "primaryIPv4Address": "10.1.0.5",
    "ruleName": "UserRule_Port_3389",
    "direction": "In",
    "priority": 100,
    "type": "allow",
    "conditions": {
        "protocols": "6",
        "sourcePortRange": "0-65535",
        "destinationPortRange": "3389-3389",
        "sourceIP": "0.0.0.0/0,0.0.0.0/0",
        "destinationIP": "0.0.0.0/0,0.0.0.0/0"
    }
}
- The log doesn't capture information about the source IP
## NSG Flow Log Format (with example)
Rule:
```
"rule": "DefaultRule_AllowInternetOutBound",
"flows": [{"mac": "00OD3AEC9DC6", "flowTuples":["1680307155,10.1.0.5,20.189.172.18,63122,443,T,O,A,E,16,29337,21,14333"
```
Time stamp: 1680307155 (Time stamp of when the flow occurred in UNIX epoch format)
Source IP: 10.1.0.5 (Source IP address)
Destination IP: 20.189.172.18 (Destination IP address)
Source port: 63122 (Source port)
Destination port: 443 (Destination port)
Protocol: T (Protocol of the flow. Valid values are **T** for TCP and **U** for UDP)
Traffic flow: O (Direction of the traffic flow. Valid values are **I** for inbound and **O** for outbound)
Traffic decision: A (Whether traffic was allowed or denied. Valid values are **A** for allowed and **D** for denied)

## NSG Flow Log Format (with example)
Rule:
```
"rule": "DefaultRule_AllowInternetOutBound",
"flows": [{"mac": "00OD3AEC9DC6", "flowTuples":["1680307155,10.1.0.5,20.189.172.18,63122,443,T,O,A,E,16,29337,21,14333"]
```

**Flow state:** E
	State of the flow. Possible states are:
	• **B**: Begin, when a flow is created. Statistics aren’t provided.
	• **C**: Continuing for an ongoing flow. Statistics are provided at 5-minute intervals.
	• **E**: End, when a flow is terminated. Statistics are provided.
**Packets sent:** 16 (Total number of TCP packets sent from source to destination since the last update)
**Bytes sent:** 29337 (Total number of TCP packet bytes sent from source to destination since the last update)
**Packets received:** 21 (Total number of TCP packets sent from destination to source since the last update)
**Bytes received:** 14333 (Total number of TCP packet bytes sent from destination to source since the last update)

## Storage Account Logs Fields
category
	StorageRead
	StorageWrite
	StorageDelete
operationName
	GetBlob
	Read
	Microsoft.Storage/storageAccounts/somename
	Microsoft.Storage/storageAccounts/LISTKEYS
statusText
	Success
	Failure
callerIpAddress: Origin of the request
identity: important for use to track which access key may have been compromised
    type: Credentials used for access
	    SAS
    tokenHash: 
	    key1(xxx)
properties
    accountName: Storage account accessed
    userAgentHeader: Application that made the request
    responseBodySize: Size of the file downloaded
uri: Path with filename
## Storage Account Logs Fields (example)
"category": "StorageRead",
"operationName": "GetBlob",
"statusText": "Success",
"callerIpAddress": "85.206.166.82:24165",
	"identity": {
	    "type": "SAS",
	    "tokenHash": "key1(xxx)"},
"properties": {
    "accountName": "researchlabstore",
    "userAgentHeader": "Microsoft Azure Storage Explorer, 1.18.1, win32, azcopy-node, 2.0.0, win32, AzCopy/10.8.0 Azure-Storage/0.10 (go1.13: Windows_NT)",
    "responseBodySize": 1691546
},
"uri": "https://researchlabstore.blob.core.windows.net/secretproject/Truth_serum.7z?se=2021-05-07T00:01:13Z&sig=XXXXX&sp=rl&rsr=c&sv=2020-04-08&timeout=901"

## Data Exfiltration: Generate Keys (example)
operationName:
	"MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION": important to check to confirm if any principal has enumerated the storage credentials

## Important Permissions
"Microsoft.Compute/virtualMachines/runCommand/write": required to execute a run command, part of the **Virtual Machine Contributor** role as well as other higher-level roles.

## LinuxSysLogVer2v0 Fields
**EventTime**: The time at which the event occurred. The log contains numerous timestamps, but this is the most important one.
**Facility**: Represents the machine process that created the event, ie, kernel, SSH daemon, mail system
**Host**: The name of the machine (there is a redundant field called hostname).
**Msg**: The most important field that contains the actual event.
**Severity**: As described in the previous slide.
**Ident**: The process that generated the event.
**Pid**: The process ID.
syslog_program: examples include systemd, systemd-login, sshd, cron
message: Description of the event, ie, "Accepted password for Scott from 45.56.183.51 port 53501 ssh2"

## Other M365 Examples

Looking for the locations that a user account attempted sign-ins from:
```
user_ids: "admin@pymtechlabs.com" AND source_geo.country_name: *
```

Which users utilised a device authorisation flow to sign-in?

```
signInEventTypes: deviceCodeFlow AND signInEventTypes: interactiveUser
```

Which users consented to adding OAuth applications?
```
operationName: "Consent to application"
```

Which Graph API endpoint did an attacker use to gain a foothold?

Given the Service Principal Name:
```
<SPN> AND properties.requestUri: **
```

What role did the user consent to for the app?
- Review `modified_properties`

## Other Azure Examples
Looking for role assignment log entries by admin@pymtechlabs.com (these would be "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" events):
```
user_principal_name: "admin@pymtechlabs.com" AND operation_name: (* AND NOT "Sign-in activity")
```

How many successful logins for Luis?
```
user_name: "luis@pymtechlabs.com" AND result_type: 0
```

What is the name of the script file accessed within blob storage?

Start with:
```
azure-eventhub.eventhub: "bloblogs"
```
- Then review the fields azure.resource.name, azure.eventhub.properties.objectKey, azure.eventhub.operationName, azure.eventhub.statusText

What is the display name of the user account?
```
azure.signinlogs.properties.user_display_name: *
```

What is the name of the VM that the attacker started?
```
azure.activitylogs.identity.claims_initiated_by_user.name.keyword: * AND event.action: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
```
