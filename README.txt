"COMS 4180 Network Security Group Project"
==========================================

* Warning:
        a) All Certificates must be in the same folder. Names should not be
           changed as they have been hardcoded.
        b) Server keeps it's files in the directory server_files and client
           in tmp_client. Don't change them as they are hardcoded too.

*How to set up?

To set up the environment in a GCE Ubuntu 16.04 VM:
    1) Clone this repository (let's say REPO_PATH=~/netsec-proj)
    2) sudo apt-get install -y python3-pip
    3) cd ${REPO_PATH}
    4) pip3 install -r requirements.txt


*How to Run?

Note: Run the server first else you will encounter a "Connections closed"
      error

Method 1:-
        Type make server and make client. This supplies the Server and Client
        with default values of port number. The only caveat is that it runs
        on localhost. If you want to test on different IPs, check Method 2
        of this section.
        As is common, run the server first.

Method 2:-
        server: ./server.py <port> <cert> <key> <client_cert>
        client: ./client.py <host> <port> <cert> <key> <server_cert>
        where:-
        <port>          : Port Number on which server is running.
        <host>          : IP Address/FQDN of the server on which the Server is
                              hosted/Client will connect
        <cert>          : The .pem file containing that entity's certificate.
        <key>           : The .pem file containing the private key that signs
                              that entity's certificate.
        <*_cert>        : The .pem file containing the other entity's
                              certificate.
        Eg:
        Server          : ./server.py 5000 server_cert.pem server_key.pem client_cert.pem
        Client          : ./client.py 127.0.0.1 5000 client_cert.pem client_key.pem server_cert.pem


*Supported Commands and Formats:
        1) put <filename> <enc-flag> <opt-password>
                This command encrypts the file and stores it in
                /server_files directory of the server.
        2) get <filename> <enc-flag> <opt-password>
                Tries to get the file from the server and stores it in
                /tmp_client directory of the client.
        3) stop
                Closes the socket and exits.
        4) The server stores the file and its SHA256 hash in server_files folder.
	      5) The client stores the file in tmp_client folder.


* Generating Certificates:
        We invoke a bash script that uses the openssl cert command to generate
        the certificate and the private key.
        a) For server:-
          ./create_cert.sh server

        b) For client:-
          ./create_cert.sh client
