# Marshalling utilities for =nil;Crypto3 Multiprecision

This module provides extension of [=nil;Marshalling](https://github.com/NilFoundation/marshalling) utilities for [=nil;Crypto3 Multiprecision](https://github.com/NilFoundation/crypto3-multiprecision)

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git). To actually include this
library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look
   at [crypto3](https://github.com/nilfoundation/crypto3.git) for the example)

## Dependencies

### Internal

* [Multiprecision](https://github.com/nilfoundation/crypto3-multiprecision.git)
* [=nil;Marshalling](https://github.com/NilFoundation/marshalling)

### External

* [Boost](https://boost.org) (>= 1.81)
