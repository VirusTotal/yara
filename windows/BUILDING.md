# Building YARA with Visual Studio

**Do not check in upgraded versions of the solution, the projects or any rebuilt lib binaries.**

In an effort to make Windows development a little easier, Visual Studio solutions are included under the `yara/windows` directory. The current project has binary dependencies checked into the repo, but this is not a good strategy long term. As build tools are updated and old versions are deprecated, there needed to be a more maintainable solution that didn't cause binary bloat in the repo.

Support for new versions of Visual Studio should be added as submodules. This allows the binary dependencies to exist outide of the main repo and also makes downloading the projects optional.

## Quick Start VS2010 (legacy)

The core yara project include binary libs (`jansson` and `libeay`) compiled with VS2010. To build the project, simply open up the `yara/windows/yara/ara.sln` and build thr project.

*Do not check in *upgrades* to the solution or project files and do not check in binary updates to this repo. The 2010 tool chain is included in the repo because it was added before the decision to separate out support for VS versions. To support new versions of Visual Studio, add a submodule instead.*

## Quick Start VS2015

VS2015 projects are included as a submodule that must be downloaded manually. To download the VS2015 project, run the following git command

  git submodule update --init windows/yara-VS2015

This will unpack the submodule into `yara/windows/yara-VS2015`. Open the `yara/windows/yara-VS2015/yara-2015.sln` and build as normal.

Read the included README for information on keeping the submodule updated and how to submit changes to the `yara-VS2015` project.

## Other versions

You can use other versions of Visual Studio as long as you have the VS2010 tool chain installed. Do not upgrade the project files and do not check in modificaitions to the solution or the project files.

## Dependencies

The Windows version of yara requires OpenSLL and JSON libraries. These can be built from source or you can reference the tool-chain specific binaries in the `lib` folder.i
