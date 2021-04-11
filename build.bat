@echo off

wuffs-c gen -package_name pe -genlinenum < pe.wuffs > parse.c
cl main.c /I "..\..\go\src\github.com\google\wuffs\release"
