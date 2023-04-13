# Proof of concept: struttura dati che contiene la configurazione dello switch
La nuova versione dello switch potrebbe produrre un file json, strutturato nel seguente modo:
```json
{
  "ds" : [{
    "showinfo" : {
      "type" : "command",
      "syntax" : "",
      "info" : "show ds info",
    },
    "help" : {
      "type" : "command",
      "syntax" : "[arg]",
      "info" : "Help (limited to arg when specified)",
    },
    ...
  }],
  "debug" : [
    ...
  ],
  ...
}
```
La nuova versione di vdetelweb quindi potrebbe prendere il file da una posizione nota (per esempio `/etc/vde/vdeswitch/settings.json`) e parsarlo (attraverso una libreria come [jsmn](https://github.com/zserge/jsmn)) e creare il menù.