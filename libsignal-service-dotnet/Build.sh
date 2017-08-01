cmd.exe /C "dotnet restore"
cmd.exe /C "dotnet pack --include-symbols --include-source"
#nuget add bin\\Debug\\libsignal-service-dotnet.1.5.3.2.nupkg -Source %NUGET_REPOSITORY%"