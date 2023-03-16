# Proof of concept: modi alternativi per trovare il ctl dir dello switch

Struttura attuale della funzione:
```c
int open_vde_mgmt(char *mgmt) {
  struct sockaddr_un sun;
  int fd, n;
  char buf[BUFSIZE + 1], *line2, *ctrl;
  sun.sun_family = PF_UNIX;
  snprintf(sun.sun_path, UNIX_PATH_MAX, "%s", mgmt);

  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)(&sun), sizeof(sun)) < 0)
    printlog(LOG_ERR, "Error connecting to the mgmt socket '%s': %s", mgmt, strerror(errno));

  if ((n = read(fd, buf, BUFSIZE)) <= 0)
    printlog(LOG_ERR, "Error reading banner from VDE switch: %s", strerror(errno));

  buf[n] = 0;
  if ((ctrl = rindex(buf, '\n')) != NULL)
    *ctrl = 0;
  banner = strdup(buf);

  if (write(fd, "ds/showinfo\n", 12) < 0)
    printlog(LOG_ERR, "Error writing ctl socket from VDE switch: %s", strerror(errno));
  if ((n = read(fd, buf, BUFSIZE)) <= 0)
    printlog(LOG_ERR, "Error reading ctl socket from VDE switch: %s", strerror(errno));

  buf[n] = 0;
  if ((line2 = index(buf, '\n')) == NULL)
    printlog(LOG_ERR, "Error parsing first line of ctl socket information");

  line2++;
  if (strncmp(line2, "ctl dir ", 8) != 0)
    printlog(LOG_ERR, "Error parsing ctl socket information");

  for (ctrl = line2 + 8; *ctrl != '\n' && ctrl < buf + n; ctrl++)
    ;

  *ctrl = 0;
  ctrl = line2 + 8;
  set_prompt(ctrl, nodename);

  iothstack = ioth_newstack("vdestack", ctrl);
  ifnet = ioth_if_nametoindex(iothstack, "vde0");

  if (ioth_linksetupdown(iothstack, ifnet, UP) < 0)
    printlog(LOG_ERR, "Error: link set up failed: %s", strerror(errno));

  return fd;
}
```

Il codice sopra apre scrive il comdando `ds/showinfo` su un nuovo socket aperto appositamente per questa opezione
e esegue parsing dell'output del comando per trovare il file che rappresenta lo switch sulla rete.

## Input dell'utente
La nuova versione dello switch potrebbe stampare informazioni di base all'avvio del programma sul terminale dell'utente, come:

```
# vde_switch -M /tmp/vde.mgmt
Switch ctl dir /tmp/vde.ctl
Mangement file at /tmp/vde.mgmt

vde$ 
```

In questo modo sarà a cura dell'utente, quando avvierà l'applicazione, di inserire i giusti parametri:
```
# vdetelweb -swt --switch vde:/// /tmp/vde.mgmt
```

Il vantaggi principali di questo approccio sono la facilità di realizzazione (in quanto, sia per il codice dello switch che per
quello di vdetelweb, sarebbero poche linee di codice in più) e il poter dare informazioni in più all'utente che possano essere
utili anche per altri programmi vde (ad esempio, vdens già prende in input il ctl dir).
Lo svantaggio principale consiste nell'informare e istruire l'utente su una opzione in più, quindi andrebbe inserita una descrizione
dettagliata sul readme e sulla man pages. Sarebbe un point of failure del programma in più e se è poco chiaro, l'utente potrebbe non
essere in grado di utilizzare il tool.

## Automattizzato
La nuova versione dello switch potrebbe stampare informazioni di base su un file.
Il file potrebbe essere:

    1. un file a cui può accedere solo il singolo processo dello switch
    2. un file comune conosciuto nell'ambiente vde

All'avvio del comando `vde_switch -M /tmp/vde.mgmt` l'opzione [1] creerebbe un file del tipo `/tmp/vde.mgmt.info` con dentro scritto
l'indirizzo della ctl dir dello switch.
In questo modo all'avvio di `vdetelweb` sarebbe facile recuperare il file in quanto basta aggiungere un `.info` al file di managment.
Se non viene specificata l'opzione `-M` per lo switch non viene creato il file, oppure bisogna trovare una convenzione diversa per il nome.

I vantaggi di questo approccio sono la completa automazione del processo e il fatto che assicura che UNA istanza del processo vdetelweb
gestisce UN singolo processo di uno switch virtuale.
Lo svangaggio principale è che bisogna documentare questa convenzione per chi si approccia al codice di questo e di altri progetti vde,
per fare in modo che nessuno la cambi e che continui a funzionare.

All'avvio del comando `vde_switch -M /tmp/vde.mgmt` l'opzione [2] creerebbe un file comune, tipo `/tmp/vdeswitch.ctls`, su cui scrivere le
proprie informazioni:

```
---switch 1---
ctl dir /tmp/vde.ctl
mgmt /tmp/vde.mgmt
--------------
---switch 2---
ctl dir /run/vde.ctl
mgmt /tmp/aaaa.mgmt
--------------
```
Con questo approccio, all'avvio di `vdetelweb` si prenderebbero le informazioni in automatico. Però se ci sono più switch avviati (è un caso possibile?0)
andrebbe chiesto all'utente di selezionare quale switch usare.

I vantaggi e gli svantaggi sono simili al caso precedente, ma con l'incognita di come gestire più switch.

Il file potrebbe essere in un formato personalizzato o in un formato standart (json, yaml, etc...) in modo da usare delle librerie
che parsano con sicurezza le informazioni.