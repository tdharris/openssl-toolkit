#!/bin/bash

# Variables
default_timeout=3
isSelfSigned=false
certificateFiles="*.key *.csr *.crt *.cert *.der"

bold() { ansi 1 "$@"; }
italic() { ansi 3 "$@"; }
underline() { ansi 4 "$@"; }

function askYesOrNo {
    REPLY=""
    while [ -z "$REPLY" ] ; do
        read -ep "$1 $YES_NO_PROMPT" REPLY
        REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
        case $REPLY in
            $YES_CAPS ) return 0 ;;
            $NO_CAPS ) return 1 ;;
            * ) REPLY=""
        esac
    done
}

# Initialize the yes/no prompt
YES_STRING=$"y"
NO_STRING=$"n"
YES_NO_PROMPT=$"[y/n]: "
YES_CAPS=$(echo ${YES_STRING}|tr [:lower:] [:upper:])
NO_CAPS=$(echo ${NO_STRING}|tr [:lower:] [:upper:])

# Certificate functions
function certPath {
    while [ true ];do
        read -ep "Enter path to store certificate files: " certPath;
        if [ ! -d $certPath ]; then
            if askYesOrNo $"Path does not exist, would you like to create it now?"; then
                mkdir -p $certPath;
                break;
            fi
        else break;
        fi
    done
}

function newCertPass {
    while :
        do
            read -p "Enter password for private key: " -s -r pass;
            printf "\n";
            read -p "Confirm password: " -s -r passCompare;
            if [ "$pass" = "$passCompare" ]; then
                echo
                break;
            else
                    echo -e "\nPasswords do not match.\n";
            fi
        done
}

function createCSRKey { 
    #Start of Generate CSR and Key script.
    certPath
        cd $certPath;
        echo -e "\nGenerating a Key and CSR";
        newCertPass
        
    echo ""                                                                                                                                                                                            1,1           Top
    openssl genrsa -passout pass:${pass} -des3 -out server.key 2048;
    openssl req -sha256 -new -key server.key -out server.csr -passin pass:${pass};
    key=${PWD##&/}"/server.key";
    csr=${PWD##&/}"/server.csr";

    echo -e "\nserver.key can be found at "$key;
    echo -e "server.csr can be found at "$csr;
}

function signCert {
    # Presuming we are in the certPath directory
    isSelfSigned=true
    crt=${PWD##&/}"/server.crt"
    echo -e "\nSigning certificate."
    if [ -f $key ] && [ -f $csr ];then
        read -ep "Enter amount of days certificate will be valid for(ie. 730): " certDays;
        if [[ -z "$certDays" ]]; then
            certDays=730;
        fi
        openssl x509 -req -sha256 -days $certDays -in $csr -signkey $key -out $crt -passin pass:${pass} 2>/dev/null;
        echo -e "Server certificate created at $crt";
        else 
            echo "Could not find server.key or server.csr in "${PWD##&/};
    fi
}

function createSelfSignedCertificate {
    echo -e "\nNote: The following will create a CSR, private key and generate a self-signed certificate.\n"
    createCSRKey
    signCert
    createPEM
}

# TODO: fix password prompts, error checking...
function createPEM {
    echo -e "\nCreating PEM..."
    
    # Ask for files/path if not self-signed
    if (! $isSelfSigned); then
        echo -e "Please provide the private key, the public key or certificate, and any intermediate CA or bundles.\n"
        read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
        if [ -d $path ];then 
            cd $path;
            ls --format=single-column | column
            if [ $? -eq 0 ]; then
                echo ""
                while true;
                do
                    read -ep "Enter private key filename (key): " key;
                    read -ep "Enter public key filename (crt): " crt;
                    if [ -f "$key" ] && [ -f "$crt" ];then
                        break
                    else echo -e "Invalid filename.\n";
                    fi
                done
                grep -iq "ENCRYPTED" $key
                if [ $? -eq 0 ]; then
                    newCertPass
                fi
            else
                echo -e "Cannot find any or all certificates files.";
            fi
        else echo "Invalid file path.";
        fi 
    fi

    # Create PEM
    if [ -f "$key" ] && [ -f "$crt" ];then
        # Removing password from Private Key, if it contains one
        echo "running openssl..."
        openssl rsa -in $key -out nopassword.key -passin pass:${pass} 2>/dev/null;
        if [ $? -eq 0 ]; then
            cat  nopassword.key > server.pem;
            rm -f nopassword.key;
            cat $crt >> server.pem;
            
            if (! $isSelfSigned); then
                while [ true ];
                do
                crtName=""
                echo
                if askYesOrNo $"Add intermediate certificate?";then
                    ls --format=single-column | column
                    read -ep "Intermediate filename: " crtName;
                    if [ ! -z "$crtName" ];then
                        cat $crtName >> server.pem;
                    fi
                else
                    break;
                fi
                done
            fi
            echo -e "Creating server.pem at "${PWD##&/}"/server.pem\n";
        else echo "Invalid pass phrase.";
        fi
    else echo "Invalid file input.";
    fi
}

function verifyCSRPrivateKeyPair {
    echo -e "\nPlease provide the CSR public key and private key\n"
    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
    if [ -d $path ];then 
        cd $path;
    echo "Listing certificate files..."
        ls -l "$certificateFiles" 2>/dev/null;
        if [ $? -ne 0 ]; then
            echo -e "\nCould not find any certificate files (.key, .crt, *.csr). Listing all:";
            ls
        fi
        echo
        read -ep "Enter the private key (.key): " key;
        read -ep "Enter the CSR: " csr;
        if [ -f ${PWD}"/$key" ]  && [ -f ${PWD}"/$csr" ]; then
            echo
            key=`openssl rsa -noout -modulus -in $key | openssl md5`
            csr=`openssl req -noout -modulus -in $csr | openssl md5`
            echo
            if [ "$key" == "$csr" ]; then
                echo "CSR is a public key of the private key."
            else echo "Invalid pair! CSR is not a public key of the private key."
            fi
            echo "key: " $key
            echo "csr: " $csr
        else
            echo -e "Invalid file input.";
        fi
    fi
}
function verifyServerCertificatePrivateKeyPair {
    echo -e "\nPlease provide the private key and the public key/certificate\n"
    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
    if [ -d $path ];then 
        cd $path;
    echo "Listing certificate files..."
        ls -l "$certificateFiles" 2>/dev/null;
        if [ $? -ne 0 ]; then
            echo -e "\nCould not find any certificate files (.key, .crt). Listing all:";
            ls
        fi
        echo
        read -ep "Enter the private key (.key): " key;
        # read -ep "Enter the CSR: " csr;
        read -ep "Enter the public key (.crt): " crt;
        if [ -f ${PWD}"/$key" ]  && [ -f ${PWD}"/$crt" ]; then
            echo
            crt=`openssl x509 -noout -modulus -in $crt | openssl md5`
            key=`openssl rsa -noout -modulus -in $key | openssl md5`
            # csr=`openssl req -noout -modulus -in $csr | openssl md5`
            echo
            if [ "$crt" == "$key" ]; then
                echo "Certificates have been validated."
            else echo "Certificate mismatch!"
            fi
            echo "key: " $key
            # echo "csr: " $csr
            echo "crt: " $crt
        else
            echo -e "Invalid file input.";
        fi
    fi
    echo -e "\nDone."
    read -p "Press [Enter] to continue."
}
function verifyChainFileAppliesToSignedCertificate {
    echo -e "\nPlease provide the root/intermediate and CA-signed certificates\n"
    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
    if [ -d $path ];then 
        cd $path;
    echo "Listing certificate files..."
        ls -l "$certificateFiles" 2>/dev/null;
        if [ $? -ne 0 ]; then
            echo -e "\nCould not find any certificate files ($certificateFiles). Listing all:";
            ls
        fi
        echo
        read -ep "Enter the file containing both root and intermediates: " cafile;
        read -ep "Enter the file containing the signed certificate: " crt;
        if [ -f ${PWD}"/$cafile" ]  && [ -f ${PWD}"/$crt" ]; then
            echo
            openssl verify -verbose -purpose sslserver -CAfile "$cafile" "$crt"
            if [ $? -eq 0 ]; then
                echo -e "\nSuccess. Certificates match to form a complete SSL chain."
            else echo -e "\nFailure. Certificates do not form a complete SSL chain."
            fi
            echo "cafile: " "${PWD}/$cafile"
            echo "crt: " "${PWD}/$crt"
        else
            echo -e "Invalid file input.";
        fi
    fi
}
function testSSLCertificateInstallation {
    # Prompt for server address
    while [ "$valid" != "true" ]; do
        read -ep "Server DNS/IP Address and port (server:port): " server;
        if [[ $server =~ .*:[[:digit:]]*$ ]]; then 
            valid=true
            else echo -e "Invalid syntax for Server DNS/IP Address. Please try again.\n"
        fi
    done

    echo -e "Testing SSL Certificate Installation..."
    timeout $default_timeout echo | openssl s_client -connect $server | less
    
}

function checkPermittedProtocols {
    # TODO: Prompt for permitted protocols (currently hard-coded)
    # default: checks if a connection other than SSL3 or TLS1 can be established

    # Prompt for server address
    while [ "$valid" != "true" ]; do
        read -ep "Server DNS/IP Address and port (server:port): " server;
        if [[ $server =~ .*:[[:digit:]]*$ ]]; then 
            valid=true
            else echo -e "Invalid syntax for Server DNS/IP Address. Please try again.\n"
        fi
    done

    echo -e "\nChecking Permitted Protocols (connection other than SSL3 or TLS1) for $server...\n"
    bad_protocol=false; bad_cipher=false;
    timeout $default_timeout openssl s_client -connect $server:443 -no_ssl3 -no_tls1
    if [ $? -eq 0 ]; then
        bad_protocol=true
    fi
    timeout $default_timeout openssl s_client -connect $server:443 -cipher NULL,LOW
    if [ $? -eq 0 ]; then
        bad_cipher=true
    fi

    # TODO: Handle other errors: dns lookup for hostname fails, fail to connect
    if($bad_protocol || $bad_cipher); then
        echo -e "\nAn unpermitted protocol can be established!";
        else echo -e "\nOnly permitted protocols can be established. No problems detected."
    fi

}

function output {
    echo -e "\nPlease provide the certificate file\n"
    type="$1"
    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
    if [ -d $path ];then 
        cd $path;
    echo "Listing certificate files..."
        ls -l "$certificateFiles" 2>/dev/null;
        if [ $? -ne 0 ]; then
            echo -e "\nCould not find any certificate files ($certificateFiles). Listing all:";
            ls
        fi
        echo
        read -ep "Enter the certificate: " crtFile;
        if [[ -f ${PWD}"/$crtFile" ]]; then
            echo

            if [ "$type" == "csr" ]; then
                openssl req -text -in ${PWD}"/$crtFile"
            elif [ "$type" == "crt" ]; then
                openssl x509 -text -in ${PWD}"/$crtFile"
            else echo "Invalid output type: $type"
            fi

        else
            echo -e "Invalid file input.";
        fi
    fi
}

function showBanner {
clear
echo -e "                                                        
      ____                __________     ______          ____    _ __ 
     / __ \___  ___ ___  / __/ __/ / ___/_  __/__  ___  / / /__ (_) /_
    / /_/ / _ \/ -_) _ \_\ \_\ \/ /_/___// / / _ \/ _ \/ /  '_// / __/
    \____/ .__/\__/_//_/___/___/____/   /_/  \___/\___/_/_/\_\/_/\__/ 
        /_/                                                           
"
}

function run {
    clear;
    $1 $2
    finished;
}

function finished {
    echo
    read -p "Done. Press [Enter] to continue";
}

while :
do
    showBanner
    echo -e "\n\t1. Create certificates..."
    echo -e "\t2. Verify certificates..."
    echo -e "\t3. Test connectivity..."
    echo -e "\t4. Output certificate information..."

    echo -e "\n\t0. Back"
    echo -n -e "\n\tSelection: "

    read opt
    a=true;
    case $opt in
        1) # submenu: Create
            while :
            do
                showBanner
                echo -e "\n\tCreate certificates:"
                echo -e "\t1. Self-Signed SSL Certificate (key, csr, crt)"
                echo -e "\t2. Private Key & Certificate Signing Request (key, csr)"
                echo -e "\t3. PEM with key and entire trust chain"

                echo -e "\n\t0. Back"
                echo -n -e "\n\tSelection: "
                read -n1 opt;
                case $opt in

                    1) run "createSelfSignedCertificate";;
                    2) run "createCSRKey";;
                    3) run "createPEM";;

                    /q | q | 0)break;;
                    *) ;;

            esac
            done
            ;;
        
        2) # submenu: Verify
            while :
            do
                showBanner
                echo -e "\n\tVerify certificates:"
                echo -e "\t1. CSR is a public key from the private key"
                echo -e "\t2. Signed certificate is the public key from the private key"
                echo -e "\t3. Chain file applies to the signed certificate (complete ssl chain)"

                echo -e "\n\t0. Back"
                echo -n -e "\n\tSelection: "
                read -n1 opt;
                case $opt in

                    1) run "verifyServerCertificatePrivateKeyPair";;
                    2) run "verifyCSRPrivateKeyPair";;
                    3) run "verifyChainFileAppliesToSignedCertificate";;

                    /q | q | 0)break;;
                    *) ;;

            esac
            done
            ;;

        3) # submenu: Test
            while :
            do
                showBanner
                echo -e "\n\tTest connectivity:"
                echo -e "\t1. SSL Certificate handshake"
                echo -e "\t2. Permitted Protocols"

                echo -e "\n\t0. Back"
                echo -n -e "\n\tSelection: "
                read -n1 opt;
                case $opt in

                    1) run "testSSLCertificateInstallation";;
                    2) run "checkPermittedProtocols";;

                    /q | q | 0)break;;
                    *) ;;

            esac
            done
            ;;
        
        4) # submenu: Info
            while :
            do
                showBanner
                echo -e "\n\tOutput certificate information:"
                echo -e "\t1. Output the details from a certifticate sign request"
                echo -e "\t2. Output the details from a signed certificate"

                echo -e "\n\t0. Back"
                echo -n -e "\n\tSelection: "
                read -n1 opt;
                case $opt in

                    1) run "output" "csr";;
                    2) run "output" "crt";;

                    /q | q | 0)break;;
                    *) ;;

            esac
            done
            ;;
        
        /q | q | 0)break;;
        *) ;;

    esac
    done