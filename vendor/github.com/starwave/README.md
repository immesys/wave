STARWAVE
========

What is STARWAVE?
-----------------
STARWAVE is an extension of WAVE's authorization system that is designed to be _self-enforcing_. A subscription DoT chain from the authority for a resource grants a secret key for decryption; publishers to that resource encrypt using the ID of that resource.

How much of WAVE's authorization system does STARWAVE support?
--------------------------------------------------------------
So far, we have a design that supports the following:
* Prefixes
* Expiry
* Delegation of authority
* Minimum-path permissions
* Out-of-order creation

The implementation is still in the works.
