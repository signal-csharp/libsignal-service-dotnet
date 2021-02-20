# Verify protoc is available and version is 3.12.4

$userdir = $env:USERPROFILE

$protobufPath = $userdir + '/.nuget/packages/google.protobuf.tools/3.12.4/tools/windows_x64/protoc.exe'

try {
    $output = & $protobufPath --version
}
catch {
    Write-Error "Could not find protoc. Did you restore NuGet packages (dotnet restore) or is your NuGet cache not in your home directory?"
    return
}

$expectedVersion = "3.12.4"
$version = $output.Split(" ")[1]

if ($version -ne $expectedVersion) {
    Write-Error "protoc version must be $expectedVersion!"
    return
}

& $protobufPath --csharp_out=. Provisioning.proto
& $protobufPath --csharp_out=. SignalService.proto
& $protobufPath --csharp_out=. WebSocketResources.proto

Move-Item -Force Provisioning.cs ../push/ProvisioningProtos.cs
Move-Item -Force SignalService.cs ../push/SignalServiceProtos.cs
Move-Item -Force WebSocketResources.cs ../websocket/WebSocketProtos.cs
