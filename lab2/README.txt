For Project 1 or Project 2:

1. Navigate to the src directory.
2. Open a command line terminal in the directory.
3. Compile the Alice and Bob files by running the following command in the src directory:

javac Project{#}_Alice.java Project{#}_Bob.java ({#} is replaced by the Project Number (1, 2 or 3)

4. Then run the Bob file first using the command below in the src directory, as it has to listen and accept Alice's socket:

java Project{#}_Bob

5. Create a new terminal in the same directory and run the Alice file using the command below:

java Project{#}_Alice

6. This should start the program and show the step by step authentication protocol process.

For Project 3:

1. Steps 1 and 2 from before are the same.
2. Compile the Alice, Bob and Attacker files by running the following command:

javac Project3_Alice.java Project3_Bob.java Project3_Attacker.java

5. Steps 4 and 5 from before can be followed if the true Alice wants to send a message to Bob.

6. To simulate a replay attack, run Bob using Step 4 from before. Then run the attacker file by using the command below:

java Project3_Attacker

The used nonces are stored in the usedNonces.txt file in the src directory, Bob reads from this and knows whether the Nonce has been used before, indicating whether it is a replay attack or not.