# WAVE is an Authentication Verification Engine

This is version 3 of WAVE, which is not yet ready for production use. If you are looking for the widely-deployed BOSS WAVE system, please go to [github.com/immesys/bw2](https://github.com/immesys/bw2)

## What's new
WAVE version 3 is no longer built on top of a blockchain, instead we have a horizontally scalable VLDM-based storage tier. We also have increased privacy of Attestations (formerly Delegations of Trust or DOTs) by adding a reverse-discoverable decryption mechanism.

## Basic tutorial

Grab a release from the [release tab](https://github.com/immesys/wave/releases). This will contain two binaries: `waved` which runs as a background process providing wave services, and `wv` the command line utility. We hope to have an installer in the near future, but for now you can either run `waved` with systemd (a unit file is provided) or in another tab.

### Creating some entities to work with

Lets create some entities to represent an organisation:

```
./wv mke -o company.namespace --nopassphrase
wrote entity: company.namespace
./wv mke -o alice --nopassphrase
wrote entity: alice
```

Lets also create a `permission set` which is an entity that uniquely identifies the meaning of a set of permission strings. This is so that one person's idea of what `read` means doesn't accidentally get confused with another person's idea. It is likely that an application developer would create a permission set for their application:

```
./wv mke -o myapp --nopassphrase
```

### Granting permissions

Now lets say that the company grants alice the permission to read all resources within the company namespace.

```
./wv rtgrant --attester company.namespace --indirections 5 --subject alice myapp:read@company.namespace/*
wrote attestation: att_GyBM5VDtIDPuWYSx6Cw6XVmeFbmdZLi5hL0qy9Acl-0jyQ==.pem
published attestation
```

With this, alice should be able to prove she has permissions on a resource, like `company.namespace/foo`:

```
./wv rtprove --subject alice myapp:read@company.namespace/foo
Synchronized 3/3 entities
Perspective graph sync complete
wrote proof: proof_2018-07-25T15:48:47-07:00.pem
```

The proof has been written out to a file, anyone can verify the proof as follows:

```
./wv verify proof_2018-07-25T15\:48\:47-07\:00.pem
Referenced attestations:
 [00] Hash: GyBM5VDtIDPuWYSx6Cw6XVmeFbmdZLi5hL0qy9Acl-0jyQ==
Paths:
 [00] 00
Subject: GyBVOAZJXLDqWGncj2C-yieCwy8vsfT8QDl6u0V-ds3Z-Q==
SubjectLoc: default
Expires: 2018-08-24 15:40:58 -0700 PDT
Policy: RTree
 Namespace: GyBIOr311-I6UE_9T0lYIoIZsLZaSWRWyuz8SJsrUJs3vw==
 Indirections: 5
 Statements:
 [00] Permission set: GyDYbnBfVzeJTzUcPgFF3IeY0VuhmRSMEZwusAp_WKndJw==
      Permissions: read
      URI: *
```

This yields a `policy` that shows the permissions that the proof is proving alice has.

### Naming entities

In the above examples, we could easily refer to `alice`, `myapp` and `company.namespace` because the files existed in the current directory. We would otherwise have to refer to these entities by their full hash. To make it easier, WAVE also has a directory mechanism that allows you to name other entities and share those names with other people. Lets name the `myapp` entity `superapp`. For now we will show public names that anyone can read:

```
./wv name --attester company.namespace --public myapp superapp
name "superapp" -> "GyDYbnBfVzeJTzUcPgFF3IeY0VuhmRSMEZwusAp_WKndJw==" created successfully
```

Now lets also say that alice decides to name her company `acme` but she wants this to be a private name that only she can see:

```
./wv name --attester alice company.namespace acme
name "acme" -> "GyBIOr311-I6UE_9T0lYIoIZsLZaSWRWyuz8SJsrUJs3vw==" created successfully
```

Alice can now refer to the app permission set as `superapp.acme` because she has privately named the company namespace entity `acme` and that entity publicly named the permission set entity `superapp`:

```
./wv resolve --perspective alice superapp.acme
Perspective graph sync complete
"superapp.acme":
= Entity
  Location: default
      Hash: GyDYbnBfVzeJTzUcPgFF3IeY0VuhmRSMEZwusAp_WKndJw==
  Known as: superapp.acme
   Created: 2018-07-25 15:46:10 -0700 PDT
   Expires: 2018-08-24 15:46:10 -0700 PDT
  Validity:
   - Valid: true
   - Expired: false
   - Malformed: false
   - Revoked: false
   - Message:
```

Lets say there is another employee the company knows as bob:

```
./wv mke -o bob.ent --nopassphrase
wrote entity: bob.ent
./wv name --attester company.namespace --public bob.ent bob
name "bob" -> "GyDepqXkTWQB6zyMfBi6ZabkkWMXVTd64nJZg_9W4mXZJg==" created successfully
```

Alice can now grant permissions to bob using the names that the company created:

```
./wv rtgrant --attester alice --subject bob.acme superapp.acme:read@acme/*
wrote attestation: att_GyDe_hk7nBWHft3m61dzYa3-iHorXCDxRc0MZxRMX8NFmw==.pem
published attestation
```
