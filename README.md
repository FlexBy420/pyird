# pyird
pyird is a program for validating PlayStation 3 JB folder game backups using IRD files. It supports automatic fetching of IRD files from online database and provides detailed file-level integrity verification against the original decrypted game structure.

Installation
============
Windows
------------------------
Just download pyird_Windows.zip from [Releases](https://github.com/FlexBy420/pyird/releases/latest), extract the folder, and run the .exe.

## Using pyird

Once the program is open, click **“Select Game Folder”** and choose a folder containing `PS3_GAME`.

pyird will then attempt to **auto-load a matching IRD** file. If one is not found locally, it will fetch it from the online [PS3 IRD database](https://flexby420.github.io/playstation_3_ird_database/). You can also manually load an IRD by clicking **“Select IRD File”**.

After loading the IRD, the program will **scan and validate the game folder**, comparing each file against the IRD. The results are displayed in the table, showing:

- **File Name**
- **Size**
- **MD5 checksums**
- **Validation status** (OK, Missing, or Mismatch)  

Extra files in the folder will also be highlighted.

---

## File Locations
- **IRD Files:** Stored in an `ird` folder in the same directory as the program.  
