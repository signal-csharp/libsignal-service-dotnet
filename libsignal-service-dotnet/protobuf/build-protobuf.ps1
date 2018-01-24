$userdir = $env:USERPROFILE

$protobufPath = $userdir + '/.nuget/packages/google.protobuf.tools'

if (-not (Test-Path $protobufPath))
{
    Write-Error ('Could not find protobuf tools path at ' + $protobufPath + "`nTry restoring nuget packages")
    exit
}

$versions = Get-ChildItem $protobufPath
$protoc = $protobufPath + "/$($versions[-1].Name)/tools/windows_x64/protoc.exe"

if (-not (Test-Path $protoc))
{
    Write-Error ('Could not find protoc at ' + $protoc + "`nTry restoring nuget packages")
    exit
}

& $protoc --csharp_out=. Provisioning.proto
& $protoc --csharp_out=. SignalService.proto
& $protoc --csharp_out=. WebSocketResources.proto

Move-Item -Force Provisioning.cs ../push/ProvisioningProtos.cs
Move-Item -Force SignalService.cs ../push/SignalServiceProtos.cs
Move-Item -Force WebSocketResources.cs ../websocket/WebSocketProtos.cs
