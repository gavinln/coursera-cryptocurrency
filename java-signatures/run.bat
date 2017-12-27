@echo off
javac GenSig.java
java GenSig data.txt

javac VerSig.java
java VerSig public_key sig data.txt

