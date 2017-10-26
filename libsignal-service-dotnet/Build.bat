@echo off
dotnet restore
dotnet build
dotnet pack --include-symbols --include-source