#!/bin/bash
export CLASSPATH=".:/usr/share/java/bcprov/bcprov.jar"
java hjStreamServer.hjStreamServer "hjStreamServer/movies/cars.dat.encrypted" 127.0.0.1 9999