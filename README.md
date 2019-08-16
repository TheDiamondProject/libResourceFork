# libResourceFork ![BuildCIBadge](https://travis-ci.org/TheDiamondProject/libResourceFork.svg?branch=master)
**libResourceFork** is part of _The Diamond Project_ and is responsible for handling the legacy ResourceFork file format.

## Building
To build **libResourceFork** you will need to have a C compiler on your machine such as GCC or Clang. You will also need to have `make` installed.

To build the library you simply need to enter the following command:

```sh
make
```

This will produce an archive called `libResourceFork.a` in the project directory.
You will need to include this into your own project along with the `resourcefork.h` header file.

If you would like to run the unit tests for the project then enter the following command:

```sh
make run-all-tests
```

## License
**libResourceFork** is provided by the Diamond Project under the MIT License.
 
