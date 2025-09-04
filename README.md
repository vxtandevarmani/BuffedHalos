# BuffedHalos

<img width="675" height="215" alt="image" src="https://github.com/user-attachments/assets/27f0ebd3-b43d-403e-bd67-524abc91f34a" />

Basically uses ROPs to queue indirect syscalls and hash signatures to detect stub tampering which is more robust than tartarus & halos gate and all values are stored from output params so this PoC actually isnt doing something impractical (until CET kicks in...)

PS. Also you can change the JOP gadget to anything else thats non-volatile register I used rcx because its the only thing available
