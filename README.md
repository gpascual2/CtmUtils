# Package CtmUtils

Set of Go helper functions for random password, keys and IDs generation and verification.

## Examples

### Password
The function Password generates a random 'password like' string of the 
length requested in the parameter, using numbers, symbols, upper and 
lower case characters. The strings does not have any check digit.
Useful for encryption passwords, session or cookies ids.

    ctmUtils := ctmutils.New()
    pass1 := ctmUtils.Password(32)
    // PVq-fKv4#@vQV9Js5qsXXYD8LH1C&..f

### Key
The function Key generates a random byte key of the length requested in
the parameter. The return is a []byte. 
Useful for unique objects ids.

    ctmUtils := ctmutils.New()
    key1 := ctmUtils.Key(32)
    // de8cbcdd5f73f9901c0c7fe8350693c2e53f8d36dd17a70613c84726372ca40b


## Algorithms

More information about algorithms used can be found in Wikipedia.

https://en.wikipedia.org/wiki/ISO_6346#Check_Digit