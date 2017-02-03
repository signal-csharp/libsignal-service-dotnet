setlocal
SET GOOGLEPROTOVER=2.4.1.555
SET PATH=%PATH%;%USERPROFILE%\.nuget\packages\Google.ProtocolBuffers\%GOOGLEPROTOVER%\tools
ProtoGen -namespace="libsignalservice.websocket" -umbrella_classname="WebSocketProtos" -nest_classes=true  -output_directory="../websocket/" WebSocketResources.proto
REM ProtoGen -namespace="libsignalservice.push" -umbrella_classname="PushMessageProtos" -nest_classes=true  -output_directory="../push/" IncomingPushMessageSignal.proto 
ProtoGen -namespace="libsignalservice.push" -umbrella_classname="SignalServiceProtos" -nest_classes=true  -output_directory="../push/" SignalService.proto 
ProtoGen -namespace="libsignalservice.push" -umbrella_classname="ProvisioningProtos" -nest_classes=true -output_directory="../push/" Provisioning.proto 