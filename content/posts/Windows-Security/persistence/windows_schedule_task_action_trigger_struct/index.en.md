---
title: "Research on Triggers and Actions Data Structures of Scheduled Tasks in the Registry"
date: 2024-01-16
type: posts
draft: false
categories:
  - Windows-Security
tags:
  - windows
  - persistence
  - schtasks
  - ScheduledTask
  - internal
---

Win7 scheduled tasks didn't have schtasks but used the legacy `at` command, represented as files. Starting from Win8, the `schtasks.exe` command appeared — the modern scheduled task service.

Previously in [Deep Dive into Windows Scheduled Tasks and Malicious Hiding Techniques]({{< relref "/posts/Windows-Security/persistence/windows_schedule_task_internal" >}}), I described the general meaning of some fields in the registry but didn't research the specific content structures, especially the binary Triggers, Actions, and other fields.

By referencing public materials and the [GhostTask](https://github.com/netero1010/GhostTask/) project, I roughly outlined the differences in Triggers and Actions structures between Win8.1 and Win10, which may be useful later.

<!--more-->

Actions:

```plain
// win8.1 Actions
01,00,          // version is 0x1
66,66,          // magic
00,00,00,00,    // id
0e,00,00,00,    // sizeOfCmd
63,00,6d,00,64,00,2e,00,65,00,78,00,65,00,
1c,00,00,00,    // sizeOfArgument
2f,00,63,00,20,00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,
16,00,00,00,    // sizeOfWorkingDirectory
63,00,3a,00,5c,00,77,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00
 
// win10 Actions
03,00,              // version is 0x3 or 0x2
0c,00,00,00,        // sizeOfAuthor
41,00,75,00,74,00,68,00,6f,00,72,00,      // Author
66,66,              // magic
00,00,00,00,        // id
0e,00,00,00,        // sizeOfCmd
63,00,6d,00,64,00,2e,00,65,00,78,00,65,00,
1c,00,00,00,        // sizeOfArgument
2f,00,63,00,20,00,6e,00,6f,00,74,00,65,00,70,00,61,00,64,00,2e,00,65,00,78,00,65,00,
00,00,00,00,        // sizeOfWorkingDirectory
00,00               // flag
```

Triggers:

```plain
// win8.1 Triggers
/* header */
15,00,00,00,00,00,00,00,                          // version is 0x15
01,23,ef,30,fb,7f,00,00,00,a0,78,02,c3,18,da,01,  // startBoundary
00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,  // endBoundary
 
38,21,41,43,  // flag
48,48,48,48,  // pad0
da,93,f7,14,  // crc32
48,48,48,48,  // pad1
 
/* jobBucket->userInfo */
00,48,48,48,48,48,48,48,  // skipUser
00,48,48,48,48,48,48,48,  // skipSid
01,00,00,00,              // sidType
48,48,48,48,              // pad0
 
1c,00,00,00,              // sizeOfSid
48,48,48,48,              // pad1
01,05,00,00,00,00,00,05,15,00,00,00,d1,5c,67,0e,ff,fb,b6,c7,c4,d2,95,22,e9,03,00,00,
48,48,48,48,              // pad2
 
1e,00,00,00,              // sizeOfUsername
48,48,48,48,              // pad3
77,00,6f,00,72,00,6b,00,66,00,6c,00,6f,00,77,00,5c,00,74,00,68,00,69,00,6e,00,30,00,00,00,
48,48,                    // 4-bit alignment
 
2c,00,00,00,    // sizeOfOptionalSettings
48,48,48,48,    // pad5
/* jobBucket->optionalSettings */
58,02,00,00,    // idleDurationSeconds
10,0e,00,00,    // idleWaitTimeoutSeconds
80,f4,03,00,    // executionTimeLimitSeconds
ff,ff,ff,ff,    // deleteExpiredTaskAfter
07,00,00,00,    // priority
00,00,00,00,    // restartOnFailureDelay
00,00,00,00,\   // restartOnFailureRetries
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  // networkId
48,48,48,48,    // pad0
 
/* time trigger */
dd,dd,00,00,    // migic
00,00,00,00,    // unknown1
01,23,ef,30,fb,7f,00,00,00,a0,78,02,c3,18,da,01,  // startBoundary
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  // endBoundary
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00, 
3c,00,00,00,    // repetitionIntervalSeconds
00,00,00,00,    // repetitionDurationSeconds
ff,ff,ff,ff,    // timeoutSeconds
00,00,00,00,    // mode
00,00,          // data0
00,00,          // data1
00,00,          // data2
00,00,          // pad0
00,             // stopTasksAtDurationEnd
01,             // enabled
33,2f,          // pad1
01,00,00,00,    // unknown2
00,00,00,00,    // maxDelaySeconds
fb,7f,00,00     // pad2
 
// win10 Triggers
/* header */
17,00,00,00,00,00,00,00,
01,07,0b,00,00,00,0e,00,00,b4,75,57,13,17,da,01,
00,07,0b,00,00,00,0e,00,ff,ff,ff,ff,ff,ff,ff,ff,
 
/* jobBucket */
38,21,41,42,    // flags -> 0x42412138
        // 0x40000000: AllowHardTerminate
        // 0x20000000: Interval
        // 0x10000000: TokenSidTypeUnrestricted
        // 0x08000000: TokenSidTypeNone
        // 0x04000000: Version
        // 0x02000000: Task
        // 0x01000000: RunlevelHighestAvailable
        // 0x00800000: Hidden
        // 0x00400000: Enabled
        // 0x00080000: LogonTypeInteractivetokenorpassword
        // 0x00040000: LogonTypePassword
        // 0x00020000: LogonTypeNone
        // 0x00010000: LogonTypeInteractivetoken
        // 0x00004000: LogonTypeS4u
        // 0x00002000: ExecuteIgnoreNew
        // 0x00001000: ExecuteQueue
        // 0x00000800: ExecuteStopExisting
        // 0x00000400: ExecuteParallel
        // 0x00000200: WakeToRun
        // 0x00000100: AllowStartOnDemand
        // 0x00000080: RunOnlyIfNetworkAvailable
        // 0x00000040: StartWhenAvailable
        // 0x00000020: StopIfGoingOnBatteries
        // 0x00000010: DisallowStartIfOnBatteries
        // 0x00000008: StopOnIdleEnd
        // 0x00000004: RestartOnIdle
        // 0x00000002: RunOnlyIfIdle
48,48,48,48,    // pad0
65,f9,6c,38,    // crc32
48,48,48,48,    // pad1
0e,00,00,00,    // sizeOfAuthor
48,48,48,48,    // pad2
41,00,75,00,74,00,68,00,6f,00,72,00,00,00,
48,48,          // 4-bit alignment
00,00,00,00,    // displayName
48,48,48,48,    // pad4
 
/* jobBucket->userInfo */
00,48,48,48,48,48,48,48,\       // skipUser
00,48,48,48,48,48,48,48,        // skipSid
01,00,00,00,                    // sidType
48,48,48,48,                    // pad0
1c,00,00,00,                          // sizeOfSid
48,48,48,48,                    // pad1
01,05,00,00,00,00,00,05,15,00,00,00,a5,e3,f0,7f,04,20,c2,61,2b,10,c5,32,e9,03,00,00,
48,48,48,48,                    // pad2
2c,00,00,00,                          // sizeOfUsername
48,48,48,48,                    // pad3
44,00,45,00,53,00,4b,00,54,00,4f,00,50,00,2d,00,50,00,4c,00,55,00,49,00,48,00,4e,00,49,00,5c,00,74,00,68,00,69,00,6e,00,30,00,00,00,
48,48,48,48,
 
2c,00,00,00,            // sizeOfOptionalSettings
48,48,48,48,            // pad5
/* jobBucket->optionalSettings */
58,02,00,00,      // idleDurationSeconds
10,0e,00,00,      // idleWaitTimeoutSeconds
80,f4,03,00,      // executionTimeLimitSeconds
ff,ff,ff,ff,      // deleteExpiredTaskAfter
07,00,00,00,      // priority
00,00,00,00,      // restartOnFailureDelay
00,00,00,00,      // restartOnFailureRetries
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,      // networkId
48,48,48,48,      // pad0
 
/* time trigger */
dd,dd,00,00,
00,00,00,00,
01,07,0b,00,00,00,0e,00,00,b4,75,57,13,17,da,01,        // startBoundary
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,        // endBoundary
00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,
b0,04,00,00,
00,00,00,00,
ff,ff,ff,ff,        // timeoutSeconds
00,00,00,00,
00,00,          // data0
00,00,
00,00,
00,00,
00,             // stopTasksAtDurationEnd
01,\                //enabled
e9,bd,
01,00,00,00,
00,00,00,00,
07,a9,00,00,
00,00,00,00,48,48,48,48     // triggerId
```

DynamicInfo:

```plain
// DynamicInfo structure is the same between win8.1 and win10
// On win8.1, the DynamicInfo field content is not auto-updated and is effectively unused
03,00,00,00,                    // magic
d0,2b,41,20,e8,10,da,01,        // createTime
00,00,00,00,00,00,00,00,        // lastRunTime
00,00,00,00,                    // dwTaskState
00,00,00,00,                    // dwLastErrorCode
00,00,00,00,00,00,00,00         // ftLastSuccessfulRun
```

Some tips:

- Win8 scheduled tasks primarily rely on XML files; the registry is a backup — both are needed for task execution
- Win10 scheduled tasks depend entirely on the registry; XML files are optional
- After creating a scheduled task via the registry, the Schedule service must be manually restarted to reload and activate the task
- Testing found that modifying the SD can also hide tasks — previously, the field was simply deleted
- If the minimum execution interval is less than 60s, an XML format error will appear
- Requires SYSTEM privileges, or administrator privileges to take ownership of the relevant registry keys

Detection:

- Non-Task Scheduler service processes (svchost.exe) modifying scheduled task related registry contents or permissions
