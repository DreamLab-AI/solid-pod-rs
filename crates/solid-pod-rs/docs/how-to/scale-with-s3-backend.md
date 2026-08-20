# Object-store backend status

solid-pod-rs does not ship an S3, R2, or other object-store backend. The old
`s3-backend` feature only pulled in the AWS SDK and exposed no `Storage`
implementation, so it was removed. The bundled server now rejects
`storage.type=s3` and `JSS_STORAGE_TYPE=s3` during configuration validation.

## What to use now

Use `FsBackend` for durable local storage or `MemoryBackend` for tests and
ephemeral services. If an object store is a deployment requirement, implement
the public `Storage` trait in the consuming application and test it against the
same behavioural contract as the built-in backends.

A custom object-store implementation must provide atomic `put` behaviour,
strong deterministic ETags, direct-child `list` results, and `StorageEvent`
notifications. It must also define how body and metadata updates remain
consistent when the object store cannot update them in one transaction.

Do not add `s3-backend` to a dependency feature list: Cargo will reject the
unknown feature. Do not rely on an S3 configuration silently selecting the
filesystem; unsupported storage types deliberately fail closed.

## See also

- [Swap storage backends](swap-storage-backends.md)
- [Storage abstraction](../explanation/storage-abstraction.md)
- [Storage trait reference](../reference/api.md#storage-trait)
