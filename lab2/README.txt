For Project 1 or Project 2:

1. Navigate to the src directory.
2. Open a command line terminal in the directory.
3. Compile the Alice and Bob files by running the following command:

javac Project{#}_Alice.java Project{#}_Bob.java ({#} is replaced by the Project Number (1, 2 or 3)

4. Then run the Bob file first using the command below, as it has to listen and accept Alice's socket:

java Project{#}_Bob

5. Create a new terminal in the same directory and run the Alice file using the command below:

java Project{#}_Alice

6. This should start the program and show the step by step authentication protocol process.