RD /S /Q %NUGET_REPOSITORY%\libsignal-service-dotnet\
RD /S /Q %HOMEDRIVE%%HOMEPATH%\.nuget\packages\libsignal-service-dotnet\
RD /S /Q bin
dotnet clean
dotnet restore
dotnet build
dotnet pack --include-symbols --include-source
rem nuget add bin\Debug\libsignal-service-dotnet.*.nupkg -Source %NUGET_REPOSITORY%
rem nuget push bin\Debug\libsignal-service-dotnet.*.nupkg -Source https://www.myget.org/F/somefeed/api/v2/package
