# install wolfssl
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolfssh
make
make check
make install
cd ..
# install wolfssh
git clone https://github.com/wolfSSL/wolfssh.git
cd wolfssh
./autogen.sh
./configure --with-wolfssl=/usr/local
make
make check
make install
cd ..
# install mkcert
apt install libnss3-tools
curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v*-linux-amd64
cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert
# prepare vdetelwebrc
mkdir /etc/vde
touch /etc/vde/vdetelwebrc
echo "ip4=10.0.3.10/24
defroute4=10.0.3.1
user=root
password=e8b32ad31b34a21d9fa638c2ee6cf52d46d5106b
sshcert=/root/vdetelweb/build/vdesshcert.der
httpscert=/root/vdetelweb/build/10.0.3.10.pem
httpskey=/root/vdetelweb/build/10.0.3.10-key.pem" > /etc/vde/vdetelwebrc
# prepare vdetelweb build
mkdir build
cd build
cmake ..
make
# prepare certs
openssl ecparam -name prime256v1 -outform der -genkey -out vdesshcert.der
mkcert -install
mkcert 10.0.3.10