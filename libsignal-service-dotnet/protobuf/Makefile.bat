@echo off
setlocal
SET PATH=%PATH%;%USERPROFILE%\.nuget\packages\Google.ProtocolBuffers\%GOOGLEPROTOVER%\tools
protoc --csharp_out=. Provisioning.proto
protoc --csharp_out=. SignalService.proto
protoc --csharp_out=. WebSocketResources.proto
copy /y Provisioning.cs ..\push\ProvisioningProtos.cs
copy /y SignalService.cs ..\push\SignalServiceProtos.cs
copy /y WebSocketResources.cs ..\websocket\WebSocketProtos.cs
rm *.cs