# Documentazione progetto di sistemi virtuali: ioth e sicurezza su vdetelweb

## HTTPS

Ho installato la libreria `openssl` e l'applicativo `mkcert` per installare i certificati self signed. Per crearli ho usato i seguenti comandi:
```
# mkcert -install
# mkcert 10.0.3.10
```

Il primo comando installa un CA locale nel sistema e per firefox/chromium.
Il secondo crea dei file `.pem` che sono i certificati e la chiave privata da inserire come argomenti dell'applicazione.

Per usare chiave e certificato appena creati si usa `-k ./10.0.3.10-key.pem -c ./10.0.3.10.pem` all'avvio dell'applicazione.
Nel codice mi sono limitato a sostituire da `ioth_read` a `SSL_read` e da `ioth_write` a `SSL_write` d'appertutto.

## SSH

Ho installato la libreria `wolfssh` e, con il seguente comando, ho generato la chiave usata dal server ssh per la comunicazione:
```
# openssl ecparam -name prime256v1 -outform der -genkey -out privkey.der
```

Bisogna inserire nel file di configurazione il percorso della chiave in questo modo: `sshcert=/home/geno/Desktop/vdetelweb/build/privkey.der`

## Utente e stack ioth

Ora, per avviare l'applicazione, bisogna inserire l'utente nel file di configurazione che sarà usato come autenticazione su tutte le modalità.
File che ho usato io nelle prove:
```
ip4=10.0.3.10/24
defroute4=10.0.3.1
user=geno
password=e8b32ad31b34a21d9fa638c2ee6cf52d46d5106b
sshcert=/home/geno/Desktop/vdetelweb/build/privkey.der
```

E per avviare l'applicazione si usa il comando:
```
# ./vdetelweb -stw -S vdestack /tmp/vde.mgmt -k ./10.0.3.10-key.pem -c ./10.0.3.10.pem
You can now connect with: telnet 10.0.3.10
You can now connect with: ssh geno@10.0.3.10
You can now search in your browser https://10.0.3.10
```

Attenzione: per collegarsi ad https bisogna anche inserire `:8080` dopo l'indirizzo.
Per usare http senza il layer ssl basta togliere le opzioni `-k` e `-c` dal comando.