# KernelBugTest
KernelBugTest.sys is loaded into the kernel using OSRLOADER, 
and KernelBugRing3.exe communicates with KernelBugTest.sys to implement debugging for vulnerable drivers.
# Usage：
1.Get IRP processing function：
 
 ```
 KernelBugRing3 -n DriverName -i IoControlCode
 ```

    
2.Hook IRP handler:

 ```
 KernelBugRing3 -r IrpFunction Rva
 ```
    
3.If you already know the IRP handler, you can hook it directly:
 
 ```
 KernelBugRing3 -n DriverName -r IrpFunction Rva
 ```

4.Recovery instruction:

 ```
 KernelBugRing3 -d
 ```
