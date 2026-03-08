To run, open 4 terminals in folder of project (/src/secure) and run the following commands:

Compile java files:
javac KDC_server.java client.java Attacker.java

# Terminal 1 
java KDC_server.java 

# Terminal 2
java client.java "Client A"

# Terminal 3
java client.java "Client B"

# Terminal 4
java client.java "Client C"

To run the attacker (simulating a replay attack):
java Attacker.java "Attacker"
