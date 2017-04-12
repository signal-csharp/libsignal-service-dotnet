@echo off
dotnet restore
dotnet pack --include-symbols --include-source