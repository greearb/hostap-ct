#!/bin/sh

if [ -z "$OPENSSL" ]; then
    OPENSSL=openssl
fi
export OPENSSL_CONF=$PWD/openssl.cnf
PASS=whatever
if [ -z "$DOMAIN" ]; then
    DOMAIN=w1.fi
fi
OPER_ENG="engw1.fi TESTING USE"
OPER_FI="finw1.fi TESTIKÄYTTÖ"
CNI="$DOMAIN Hotspot 2.0 Intermediate CA"
CNR="Hotspot 2.0 Trust Root CA - 99"
CNO="ocsp.$DOMAIN"
CNV="osu-revoked.$DOMAIN"
CNOC="osu-client.$DOMAIN"
SERVERNAME="osu.$DOMAIN"
DNS=$SERVERNAME
DEBUG=0
OCSP_URI="http://$CNO:8888/"
LOGO_URI="http://osu.w1.fi/w1fi_logo.png"
LOGO_HASH256="4532f7ec36424381617c03c6ce87b55a51d6e7177ffafda243cebf280a68954d"
LOGO_HASH1="5e1d5085676eede6b02da14d31c523ec20ffba0b"

# Command line over-rides
USAGE=$( cat <<EOF
Usage:\n
# -C:  SSL Commonname for Root CA ($CNR)\n
# -d:  DNS Name ($DNS)\n
# -D:  Enable debugging (set -x, etc)\n
# -g:  Logo sha1 hash ($LOGO_HASH1)\n
# -G:  Logo sha256 hash ($LOGO_HASH256)\n
# -h:  Show this help message\n
# -I:  SSL Commonname for Intermediate CA ($CNI)\n
# -l:  Logo URI ($LOGO_URI)\n
# -m:  Domain ($DOMAIN)\n
# -o:  SSL Commonname for OSU-Client Server ($CNOC)\n
# -O:  SSL Commonname for OCSP Server ($CNO)\n
# -p:  password ($PASS)\n
# -r:  Operator-english ($OPER_ENG)\n
# -R:  Operator-finish ($OPER_FI)\n
# -S:  servername ($SERVERNAME)\n
# -u:  OCSP-URI ($OCSP_URI)\n
# -V:  SSL Commonname for OSU-Revoked Server ($CNV)\n
EOF
)

while getopts "C:d:Dg:G:I:l:m:o:O:p:r:R:S:u:V:h" flag
  do
  case $flag in
      C) CNR=$OPTARG;;
      d) DNS=$OPTARG;;
      D) DEBUG=1;;
      g) LOGO_HASH1=$OPTARG;;
      G) LOGO_HASH256=$OPTARG;;
      h) echo -e $USAGE; exit 0;;
      I) CNI=$OPTARG;;
      l) LOGO_URI=$OPTARG;;
      m) DOMAIN=$OPTARG;;
      o) CNOC=$OPTARG;;
      O) CNO=$OPTARG;;
      p) PASS=$OPTARG;;
      r) OPER_ENG=$OPTARG;;
      R) OPER_FI=$OPTARG;;
      S) SERVERNAME=$OPTARG;;
      u) OCSP_URI=$OPTARG;;
      V) CNV=$OPTARG;;
      *) echo "Un-known flag: $flag"; echo -e $USAGE;exit 1;;
  esac
done

fail()
{
    echo "$*"
    exit 1
}

echo
echo "---[ Root CA ]----------------------------------------------------------"
echo

if [ $DEBUG == 1 ]
then
    set -x
fi

if [ ! -f openssl-root.cnf.orig ]
then
    cp openssl-root.cnf openssl-root.cnf.orig
else
    cp openssl-root.cnf.orig openssl-root.cnf
fi

if [ ! -f openssl.cnf.orig ]
then
    cp openssl.cnf openssl.cnf.orig
else
    cp openssl.cnf.orig openssl.cnf
fi

# Set the password and some other common config accordingly.
cat openssl-root.cnf | sed "s/@PASSWORD@/$PASS/" \
 > openssl-root.cnf.tmp
mv openssl-root.cnf.tmp openssl-root.cnf

set -x
cat openssl.cnf | sed "s/@PASSWORD@/$PASS/" |
sed "s,@OCSP_URI@,$OCSP_URI," |
sed "s,@LOGO_URI@,$LOGO_URI," |
sed "s,@LOGO_HASH1@,$LOGO_HASH1," |
sed "s,@LOGO_HASH256@,$LOGO_HASH256," |
sed "s/@DOMAIN@/$DOMAIN/" \
 > openssl.cnf.tmp
mv openssl.cnf.tmp openssl.cnf


cat openssl-root.cnf | sed "s/#@CN@/commonName_default = $CNR/" > openssl.cnf.tmp
mkdir -p rootCA/certs rootCA/crl rootCA/newcerts rootCA/private
touch rootCA/index.txt
if [ -e rootCA/private/cakey.pem ]; then
    echo " * Use existing Root CA"
else
    echo " * Generate Root CA private key"
    $OPENSSL req -config openssl.cnf.tmp -batch -new -newkey rsa:4096 -keyout rootCA/private/cakey.pem -out rootCA/careq.pem || fail "Failed to generate Root CA private key"
    echo " * Sign Root CA certificate"
    $OPENSSL ca -config openssl.cnf.tmp -md sha256 -create_serial -out rootCA/cacert.pem -days 10957 -batch -keyfile rootCA/private/cakey.pem -passin pass:$PASS -selfsign -extensions v3_ca -outdir rootCA/newcerts -infiles rootCA/careq.pem || fail "Failed to sign Root CA certificate"
    $OPENSSL x509 -in rootCA/cacert.pem -out rootCA/cacert.der -outform DER || fail "Failed to create rootCA DER"
    sha256sum rootCA/cacert.der > rootCA/cacert.fingerprint || fail "Failed to create rootCA fingerprint"
fi
if [ ! -e rootCA/crlnumber ]; then
    echo 00 > rootCA/crlnumber
fi

echo
echo "---[ Intermediate CA ]--------------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = $CNI/" > openssl.cnf.tmp
mkdir -p demoCA/certs demoCA/crl demoCA/newcerts demoCA/private
touch demoCA/index.txt
if [ -e demoCA/private/cakey.pem ]; then
    echo " * Use existing Intermediate CA"
else
    echo " * Generate Intermediate CA private key"
    $OPENSSL req -config openssl.cnf.tmp -batch -new -newkey rsa:2048 -keyout demoCA/private/cakey.pem -out demoCA/careq.pem || fail "Failed to generate Intermediate CA private key"
    echo " * Sign Intermediate CA certificate"
    $OPENSSL ca -config openssl.cnf.tmp -md sha256 -create_serial -out demoCA/cacert.pem -days 3652 -batch -keyfile rootCA/private/cakey.pem -cert rootCA/cacert.pem -passin pass:$PASS -extensions v3_ca -infiles demoCA/careq.pem || fail "Failed to sign Intermediate CA certificate"
    # horrible from security view point, but for testing purposes since OCSP responder does not seem to support -passin
    openssl rsa -in demoCA/private/cakey.pem -out demoCA/private/cakey-plain.pem -passin pass:$PASS
    $OPENSSL x509 -in demoCA/cacert.pem -out demoCA/cacert.der -outform DER || fail "Failed to create demoCA DER."
    sha256sum demoCA/cacert.der > demoCA/cacert.fingerprint || fail "Failed to create demoCA fingerprint"
fi
if [ ! -e demoCA/crlnumber ]; then
    echo 00 > demoCA/crlnumber
fi

echo
echo "OCSP responder"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = $CNO/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out ocsp.csr -keyout ocsp.key -extensions v3_OCSP
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -keyfile demoCA/private/cakey.pem -passin pass:$PASS -in ocsp.csr -out ocsp.pem -days 730 -extensions v3_OCSP || fail "Could not generate ocsp.pem"

echo
echo "---[ Server - to be revoked ] ------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = $CNV/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out server-revoked.csr -keyout server-revoked.key
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server-revoked.csr -out server-revoked.pem -key $PASS -days 730 -extensions ext_server
$OPENSSL ca -revoke server-revoked.pem -key $PASS

echo
echo "---[ Server - with client ext key use ] ---------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = $CNOC/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out server-client.csr -keyout server-client.key || fail "Could not create server-client.key"
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server-client.csr -out server-client.pem -key $PASS -days 730 -extensions ext_client || fail "Could not create server-client.pem"

echo
echo "---[ User ]-------------------------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = User/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out user.csr -keyout user.key || fail "Could not create user.key"
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in user.csr -out user.pem -key $PASS -days 730 -extensions ext_client || fail "Could not create user.pem"

echo
echo "---[ Server ]-----------------------------------------------------------"
echo

ALT="DNS:$DNS"
ALT="$ALT,otherName:1.3.6.1.4.1.40808.1.1.1;UTF8String:$OPER_ENG"
ALT="$ALT,otherName:1.3.6.1.4.1.40808.1.1.1;UTF8String:$OPER_FI"

cat openssl.cnf |
	sed "s/#@CN@/commonName_default = $SERVERNAME/" |
	sed "s/^##organizationalUnitName/organizationalUnitName/" |
	sed "s/#@OU@/organizationalUnitName_default = Hotspot 2.0 Online Sign Up Server/" |
	sed "s/#@ALTNAME@/subjectAltName=critical,$ALT/" \
	> openssl.cnf.tmp
echo $OPENSSL req -config $PWD/openssl.cnf.tmp -batch -sha256 -new -newkey rsa:2048 -nodes -out server.csr -keyout server.key -reqexts v3_osu_server
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -sha256 -new -newkey rsa:2048 -nodes -out server.csr -keyout server.key -reqexts v3_osu_server || fail "Failed to generate server request"
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server.csr -out server.pem -key $PASS -days 730 -extensions ext_server -policy policy_osu_server || fail "Failed to sign server certificate"

#dump logotype details for debugging
$OPENSSL x509 -in server.pem -out server.der -outform DER
openssl asn1parse -in server.der -inform DER | grep HEX | tail -1 | sed 's/.*://' | xxd -r -p > logo.der
openssl asn1parse -in logo.der -inform DER > logo.asn1


echo
echo "---[ CRL ]---------------------------------------------------------------"
echo

$OPENSSL ca -config $PWD/openssl.cnf -gencrl -md sha256 -out demoCA/crl/crl.pem -passin pass:$PASS

echo
echo "---[ Verify ]------------------------------------------------------------"
echo

$OPENSSL verify -CAfile rootCA/cacert.pem demoCA/cacert.pem
$OPENSSL verify -CAfile rootCA/cacert.pem -untrusted demoCA/cacert.pem *.pem

cat rootCA/cacert.pem demoCA/cacert.pem > ca.pem
