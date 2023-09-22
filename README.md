# Common Cheating Snippets/Scripts

* Pattern Scanner
* Return Address Spoofing
* Kernel-mode/User-mode Lazy Importer
* skCrypter

## What is this?

Usually people have a lot of cheating projects and these scripts are in most of them, the problem becomes when you have a bug/idea on one of them, and you change it everywhere or simply new people that comes to the scene don't know about this stuff, and they make again by themselves when it's already done by another person and probably taking care of a lot of important things

Then this is a pack of common used code for cheating

## Why no hooking library

This repo tries to get most small and dependency less scripts possible and most know hooking libraries bring a lot of files or even dependency of user-mode/kernel-mode or system APIs then i just decided not add any hooking library for now

## How to use it

Just include in your project the files that you need, you have more info in header files of every script

## Examples

* Pattern Scanner -> Kernel-mode/User-mode compatible
    * Pattern::ScanPatternInExecutableSection(module, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
    * Pattern::ScanPatternInSection(module, ".text", "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
    * Pattern::Scan(Start, memLength, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")

* Return Address Spoofing -> Kernel-mode/User-mode compatible
    * spoof_call(simulated_return_address, function_to_call, arg1, arg2...)

* Kernel-mode/User-mode Lazy Importer -> Kernel-mode/User-mode compatible
    * LI_FN(AllocConsole)()
    * LI_FN(KeBugCheck)(XBOX_360_SYSTEM_CRASH)

* skCrypter -> Kernel-mode/User-mode compatible
    * auto testString = skCrypt(L"TestString") //Warning may have issues with compiler optimization and usage in global scope


## Detections

There is no detection\* at all for using this snippets and if you think about patterns you can always use some protection software for mutation/obfuscation breaking patterns

\* Pattern scanner may be detected if VirtualQueryEx is hooked but this is only in usermode and if you enable memory checking

## Who make these snippets?

They are public and were made by different persons and their credits are at top of header files

## Contribution

Anybody can create a pull request with interesting snippets or improvements in current ones while they keep this small as possible