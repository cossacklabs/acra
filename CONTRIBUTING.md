# Contributing to Acra

Although Acra is an in-house-developed product by [Cossack Labs Limited](https://www.cossacklabs.com/),
it is still open-source, Apache 2-licensed software.
This means you can hack it in any way you want and contribute things back if you’d like to.
As a software company, we focus on implementing features that are important to our products
but would gladly spend some time on making Acra useful for everybody.

We highly encourage you to:

- Report bugs and request features via [GitHub Issues](https://github.com/cossacklabs/acra/issues).

- Report a bug and fix it with a patch via our [GitHub Pull request](https://github.com/cossacklabs/acra/pulls)
  (after creating a corresponding issue and leaving a link to the pull there).

- Add something new to Acra.
  There is a certain design scheme according to which we’d like to keep developing Acra.
  If your contributions fall along with it, we’d be glad to accept some fundamental additions.
  It’s better to discuss the subject using email before taking action (see below).

Every commit that goes into the master branch is audited and reviewed by somebody from Cossack Labs,
so don’t be surprised if it takes a bit long.

If you’d like to participate in the core development more deeply, get in touch.

## Getting in touch

- Requests/bugfixes/queries should go through [GitHub Issues](https://github.com/cossacklabs/acra/issues).

- To get in touch with the developers, use [this email](mailto:dev@cossacklabs.com) at your own discretion :)
  Make sure you’ve tried reaching out through GitHub Issues first, before writing a direct email.

- To talk to the business wing of Cossack Labs Limited, drop us [an email](mailto:info@cossacklabs.com).

## Documentation

The most recent versions of the documentation, tutorials, and demos for Acra are available on the official [Cossack Labs Documentation Server](https://docs.cossacklabs.com/products/acra/).

## Conventions

Generally, we follow common best practices established in the Go community.
Here are some additional conventions that we follow.

  - Use standard code quality tools like `gofmt` and `go lint`.

  - Error descriptions should start with a lowercase letter.

    This is consistent with Go standard library conventions.
    Error description should contain enough information to see the origin of the error.

    ```go
    // Correct:
    var ErrCannotConnect = errors.New("cannot connect to AcraService")

    // NOT like this:
    var ErrCannotConnect = errors.New("AcraService: Cannot connect")
    ```

  - Log messages should start with an uppercase letter.

    ```go
    err = frobnicate(thing)
    if err != nil {
            log.WithError(err).Debug("Cannot frobnicate thing")
            return err
    }
    ```

  - Export error constants, unless they are used only inside the package.

    If an exported function can return a particular error, it should be exported.
    Don’t force the users to match on the error string description by hiding it.

    Here is a tongue-in-cheek example for when it might be okay to not export an error.
    (That is, in *most cases* you should export them, unless you clearly see why not.)

    <details>
    <summary>Example</summary>

    ```go
    package stuff

    import "errors"

    // Possible errors when doing stuff:
    var (
            ErrEven = errors.New("even I wouldn't know")
            ErrOdd  = errors.New("odd, don't you think")
    )

    // ExportedFunction does stuff
    func ExportedFunction(n int) error {
            if n % 2 == 0 {
                    return ErrEven
            }
            return internalHelper(n)
    }

    func internalHelper(n int) error {
            err := nestedHelper(n)
            if err == errImpossible {
                    panic("the impossible happened")
            }
            return err
    }

    // Used *only* in internalHelper():
    var errImpossible = errors.New("BUG: n cannot be 0")

    func nestedHelper(n int) error {
            if n == 0 {
                    return errImpossible
            }
            if n % 2 == 1 {
                    return ErrOdd
            }
            return nil
    }
    ```

    </details>
