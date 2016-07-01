libgit2 Dependency
==================

We cannot distribute the libgit2 binaries as per the licensing which disallows binary distribution unless it is a combined work (linked).

To acquire and build the necessary libgit2 dependency:

1) Clone libgit2 from https://github.com/libgit2/
2) Build it for x86 and x64 in either Release or Debug mode
3) Copy the resulting files `git2.lib` and `git2.dll` to `./x86/` and `./x64/` for each architecture

ProcFilter will build with these files in place.
