let Package =
    { name : Text, version : Text, repo : Text, dependencies : List Text }
in
    [
      { name = "core"
      , version = "v2.6.1"
      , repo = "https://github.com/caffeinelabs/motoko-core"
      , dependencies = [] : List Text
      },
      { name = "bls12-381"
      , version = "v0.1.0"
      , repo = "https://github.com/icdevsorg/bls12-381.mo"
      , dependencies = [ "core" ] : List Text
      },
      { name = "sha2"
      , version = "0.2.5"
      , repo = "https://github.com/research-ag/sha2"
      , dependencies = [ "core" ] : List Text
      }
    ] : List Package
