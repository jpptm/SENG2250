SENG2250 - SYSTEMS AND NETWORK SECURITY ASSIGNMENT 3 PART 2
        
Author:         Johanne Montano
Student Number: C3336019

Dependencies required:
    hashlib
    socket
    secrets
    sys

As far as I am aware these libraries are all built in but if the interpreter throws an unknown module error, please try

    'pip install <library_name>'

These scripts have been tested over and over again so the output should be visible once the main scripts are executed.

The main scripts are 'server.py' and 'client.py'

Please open 2 instances of your terminal. After receiving the zip file and extracting, cd A3 (I do not know what the equivalent of cd is in macOS) and enter

'python server.py' in one instance and 'python client.py' at the other. In pc's with Ubuntu/Debian/Linux based, the command might have to be

'python3 server.py' and 'python3 client.py' instead.

Please always run the server first, and then the client. The server will be listening for possible connections and when the client script is run then it will connect to the server. 
The server will run on the PC's IP address and the client will be connecting to port 5050 by default.

At the end of the script the server will be forcing to close the connection. Sometimes, trying to rerun the script after a session will cause both scripts to get stuck on the listening part and the client_hello part/
If this happens, please exit the current terminal instances then start 2 new ones and re enter the commands as required.

For context, I was playing around with true random numbers and found secrets. I just found it interesting that they use a true random number generator by using file entropy via 'secrets.SystemRandom()'.
It is also very convenient that they can generate tokens, random hex values and random bits/bytes.

If there are any further questions/clarifications that the markers would like to ask please do not hesitate to let me know and contact me at either johanne.montano@uon.edu.au or prncmontano@gmail.com, whichever is more preferable.

Thank you very much in advance!