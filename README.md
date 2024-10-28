# HetrixTools Windows Server Monitoring Agent

Documentation available here: https://docs.hetrixtools.com/category/server-monitor/

### Changelog

#### Version 2.0.0: 

- Rewritten the entire Windows Agent in PowerShell
- Optimized metrics collection & simplified the code
- Added `CheckServices` which allows the agent to monitor the status of running processes and services
- Added `CheckDriveHealth` which allows the agent to monitor drive health
- The agent will now have a warning on the HetrixTools interface if your server needs to reboot to finish installing updates



#### Version 1.x (discontinued): 
https://github.com/hetrixtools/agent-win