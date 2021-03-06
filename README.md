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

### ID
The function GenerateID generates a random string in the "AAAA-BBBB-CCCC-DDX" format, 
where the last is a ISO6346 check digit. 
Useful for serial numbers, vouchers, etc.

    ctmUtils := ctmutils.New()
    key1 := ctmUtils.GenerateID()
    // V5ZW-UJQ6-2WT6-H55

There is also a validation function:

    ctmUtils.ValidateID("V5ZW-UJQ6-2WT6-H55")  --> true if valid

And a pair of Mask / Unmask function to switch between (AAAA-BBBB-CCCC-DDX <--> AAAABBBBCCCCDDX) formats

    ctmUtils.MaskID("V5ZWUJQ62WT6H55") --> "V5ZW-UJQ6-2WT6-H55"
    ctmUtils.UnmaskID("V5ZW-UJQ6-2WT6-H55")  --> "V5ZWUJQ62WT6H55"

## Algorithms

More information about algorithms used can be found in Wikipedia.

https://en.wikipedia.org/wiki/ISO_6346#Check_Digit