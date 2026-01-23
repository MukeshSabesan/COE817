For either Project 1 or Project 2:
To run either the SiriServer and/or SiriClient perform the following:
1. Navigate to the src directory in project-1 or project2 folder.
2. Open a command line terminal in the directory.
3. Compile the protocol, server and client .java files by running the following command:

For Project 1:
javac project\pkg1\SiriServer.java project\pkg1\SiriProtocol.java project\pkg1\SiriClient.java

For Project 2:
javac main\SiriServer.java main\SiriProtocol.java main\SiriClient.java

4. Once that is finished, you can run the SiriServer from the current terminal with the following command:

java project.pkg1.SiriServer <portnumber> (Project 1)

java main.SiriServer <portnumber> (Project 2)

The port number can be any number you choose (i.e: 4444)

5. Create a new terminal (follow steps 1 and 2) and run the SiriClient using the following command:

java project.pkg1.SiriClient localhost <portnumber> or java project.pkg1.SiriClient 127.0.0.1 <portnumber> (Project 1)

java main.SiriClient localhost <portnumber> or java main.SiriClient 127.0.0.1 <portnumber> (Project 2)

6. After this, you can ask any question you want from the client to the server, and the server should be able to respond.

7. To quit the connection from the client side, simply enter "quit" (ignore case) in the command line.