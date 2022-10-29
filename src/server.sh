#!/bin/bash
export CLASSPATH=".:/usr/share/java/bcprov/bcprov.jar"
java hjStreamServer.hjStreamServer "hjStreamServer/movies/cars.dat.encrypted" localhost 9999 224.7.7.7:7777