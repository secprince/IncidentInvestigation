        Incident response Commands


        Resolve-DnsName -Name 192.168.205.40 | select NameHost
         Resolve-Error
          Resolve-Credentials

          Get-EventLog -LogName  application | out-gridview -Title "App log events"
          Get-NetTCPConnection


          # Incident Response: Windows Cheatsheet
        # Commands for CMD / Powershell / GUI

        # Check user accounts
        lusrmgr.msc
          
          # See the user accounts for the system and the type of account it is
                net user
                Get-LocalUser
        # Check Administrators
                net localgroup administrators
                Get-LocalGroupMember Administrators


        # Check processes
                taskmgr.exe
                tasklist
                Get-Process
                wmic process get name,parentprocessid,processid
                wmic process where 'ProcessID=PID' get CommandLine


        # Check Services
                services.msc
                net start
                sc query | more
                tasklist /svc
                Get-Service | Format-Table -AutoSize


        # Task Scheduler
          # Administrative Tools (GUI)
                C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools

                schtasks
                taskmgr (Check Startup)
                wmic startup get caption,command
                Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List
                Get-ScheduledTask | Format-Table -AutoSize
                Get-ScheduledTask -TaskName Office* | Format-Table -AutoSize
        
        # Enabling / Disabling Scheduled Tasks
                Disable-ScheduledTask -taskname "Adobe Flash Player Updater"
                Enable-ScheduledTask -taskname "Adobe Flash Player Updater"


        # Registry Entries
                regedit
                reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
                reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
          
          
          # Powershell Registry
          get-psdrive
          cd HKLM:\
          set-location -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
          Get-childitem -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Run*"}
          set-location -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\
          Get-childitem -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Run*"}
  
  
        # Active Internet Connections
            netstat -ano
            Get-NetTCPConnection -LocalAddress 192.168.0.100 | Sort-Object LocalPort
            Get-NetTCPConnection -LocalAddress 192.168.0.100 | Select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Format-Table -AutoSize


        # File Sharing
            net view \\192.168.0.100
            Get-SMBShare


        # Files (in your user Profile)(C:\users\MyName)
            cd %HOMEPATH%
        
        # To view the .exe files with their path to locate them
        forfiles /D -10 /S /M *.exe /C "cmd /c echo @path"
        
        # To View files without its path and more details of the particular file extension and its modification date
        forfiles /D -10 /S /M *.exe /C "cmd /c echo @ext @fname @fdate"
        
        # To check for files modified in the last 10 days type
        forfiles /p c: /S /D -10
         
         
         # To check for file size below 6MB, you can use the file explorer’s search box and enter size:<6M
          # Powershell
          cd $env:userprofile
          Get-ChildItem -Recurse –force -ErrorAction SilentlyContinue -Include *.exe | Sort-Object Name | Format-Table Name, Fullname -AutoSize
            
            
         # Search for exe Created Last Day
              Get-ChildItem -Recurse –force -ErrorAction SilentlyContinue -Include *.exe | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) } | Sort-Object Name | Format-Table Name, Fullname -AutoSize
	     
          # Search for exe Modified Last Day
	          Get-ChildItem -Recurse –force -ErrorAction SilentlyContinue -Include *.exe | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Sort-Object Name | Format-Table Name, Fullname -AutoSize
  
  
        # Firewall Settings
          #  view the firewall configurations and the inbound and outbound traffic 
            netsh firewall show config
        
        # view the firewall settings of the current profile
            netsh advfirewall show currentprofile
          
          
          # Powershell
          Get-NetFirewallRule | select DisplayName,Direction,Action,Enabled | Where-Object Enabled -eq $true | Sort-Object Direction, DisplayName | Format-Table -AutoSize
          Get-NetFirewallProfile
  
  
        # Sessions with other systems
            net use
        
        
        # Open Sessions
            net session

            Get-SmbMapping
            Get-SmbConnection


        # Log Entries
            eventvwr.msc
            Get-EventLog -List 
        # Get Log From latest 2 hours
            Get-EventLog Application -After (Get-Date).AddHours(-2) | Format-Table -AutoSize
            Get-EventLog System -After (Get-Date).AddHours(-2) | Format-Table -AutoSize
          
        # Search for specific message
            Get-EventLog System -After (Get-Date).AddHours(-2) | Where-Object {$_.Message -like "*Server*"}

        # Check Windows Stability
            perfmon /rel 
