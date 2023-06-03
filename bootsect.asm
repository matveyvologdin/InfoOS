[BITS 16] 
[ORG 0x7c00]
start:
mov ax, cs
mov ds, ax
mov ss, ax
mov sp, start

mov al, 4
out 0x70, al
in al, 0x71
mov [0x00001000], al
mov al, 2
out 0x70, al
in al, 0x71
mov [0x00001100], al
mov al, 0
out 0x70, al
in al, 0x71
mov [0x00001200], al

mov ax, 0x1000
mov es, ax

mov bx, 0x1000
mov dl, 1
mov dh, 0
mov ch, 0
mov cl, 2
mov al, 10
mov ah, 0x02
int 0x13

mov bx, 0x3000
mov dl, 1
mov dh, 0
mov ch, 0
mov cl, 12
mov al, 7
mov ah, 0x02
int 0x13

cli
lgdt [gdt_info]

in al, 0x92
or al, 0x02
out 0x92, al

mov eax, cr0
or al, 0x01
mov cr0, eax
jmp 0x8: protected_mode 

[BITS 32] 
protected_mode:

mov ax, 0x10
mov es, ax
mov ds, ax
mov ss, ax
call 0x11000

gdt_info:
dw gdt_info - gdt 
dw gdt, 0 

gdt:
db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
db 0xff, 0xff, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00
db 0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00

times (512 - ($ - start) - 2) db 0
db 0x55, 0xAA