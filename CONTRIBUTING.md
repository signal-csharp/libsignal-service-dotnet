# Contributing to libsignal-service-dotnet

This repo aims to reflect Signal's [libsignal-service-java](https://github.com/signalapp/libsignal-service-java/). Note that libsignal-service-java was migrated into [Signal-Android](https://github.com/signalapp/Signal-Android/tree/master/libsignal/service) in December 2019.

## Building

### Requirements

1. [.NET Core 3.1 or greater](https://dotnet.microsoft.com/download)
    - Opening in Visual Studio requires Visual Studio 2019 (v16.4.0) or greater

### Steps

#### Visual Studio

1. Open the libsignal-service-dotnet.sln in Visual Studio
2. Build the solution
3. Run the tests using the Test Explorer window

#### Command Line

1. `dotnet build`
2. `dotnet test`

## Making Changes

There are two approaches to making changes
1. Commit by commit
2. By feature

### Commit By Commit

1. Find the oldest commit in libsignal-service-java that hasn't been migrated to this repo. Using version number commits from this repo will help.
    - As of February 2021 this repo is still migrating changes from the standalone [libsignal-service-java](https://github.com/signalapp/libsignal-service-java/) repo.
2. Make changes. Code migrated here should match the [Coding Guidelines](#Coding-Guidelines).
3. Test changes.
4. Commit changes with your commit message matching the commit message from libsignal-service-java. It should also include a link back to the libsignal-service-java commit in your commit description.

If the commit isn't relevant to this repo it should be skipped, for example updating Gradle or updating some dependencies. Dependencies on packages that exist in this organization (currently libsignal-metadata-dotnet, libsignal-protocol-dotnet, and curve25519-dotnet) should be reflected in this repo.

### By Feature

1. Identify the feature you want to migrate, for example stickers, and identify where in libsignal-service-java (from HEAD) that feature is implemented.
2. Make changes. This may potentially require migrating many other things in libsignal-service-java that haven't yet been migrated to this repo. If the change becomes too large it may be worth breaking the change into smaller chunks, working on and PRing those first.
3. Test changes.
4. Commit changes with your commit message including what feature you migrated. If you included specific libsignal-service-java commits you should include links to those commits in your commit description.

## Versioning

The version of this repo should generally match the latest migrated version of libsignal-service-java. This will not be the in some scenarios.
1. Important commits from previous versions of libsignal-service-java that were not migrated yet.
2. By feature commits.

In these cases a fourth number should be added or incremented on the current latest version. For example if the current version of this repo is 2.10.0 and you added a feature to enable voice calls the version number should be bumped to 2.10.0.1. If missed commits were added the version number should be bumped to 2.10.0.2. If then 1 to 1 commits were added the version number should be updated to match the version number from libsignal-service-java again. In this case it could be 2.10.1 or 2.11.0.

## Coding Guidelines

You should generally follow the Visual Studio defaults, the [C# Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions), and the [C# Naming Guidelines](https://docs.microsoft.com/en-us/dotnet/standard/design-guidelines/naming-guidelines).
