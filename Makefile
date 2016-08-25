all: Bank.class Psystem.class Customer.class

Bank.class: Bank.java
	javac Bank.java -Xlint

Psystem.class : Psystem.java
	javac Psystem.java -Xlint

Customer.class : Customer.java
	javac Customer.java -Xlint
	
clean:
	rm -f *.class 