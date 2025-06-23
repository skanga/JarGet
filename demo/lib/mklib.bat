mkdir out
javac -d out LibraryClass.java
jar cf library.jar -C out .
rmdir /s /q out