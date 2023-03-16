# Proof of concept: struttura dati che contiene la configurazione dello switch


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