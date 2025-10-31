variable "ROOT_SIGNING_VERSION" {
    type    = string
    # default = "8842feefbb65effea46ff4a0f2b6aad91e685fe9" # expired root
    # default = "9d8b5c5e3bed603c80b57fcc316b7a1af688c57e" # expired timestamp
    default = "b72505e865a7c68bd75e03272fa66512bcb41bb1"
    description = "The git commit hash of sigstore/root-signing to use for embedded roots."
}

target "tuf-root" {
    target = "tuf-root"
    output = [{
        type = "local",
        dest = "roots/tuf-root"
    }]
    args = {
        ROOT_SIGNING_VERSION = ROOT_SIGNING_VERSION
    }
}

target "validate-tuf-root" {
    target = "validate-tuf-root"
    output = [{
        type = "cacheonly"
    }]
    args = {
        ROOT_SIGNING_VERSION = ROOT_SIGNING_VERSION
    }
}

group "validate-all" {
  targets = ["lint", "lint-gopls", "validate-dockerfile", "validate-generated-files"]
}

group "validate-generated-files" {
  targets = ["validate-tuf-root"]
}

target "lint" {
  dockerfile = "./hack/dockerfiles/lint.Dockerfile"
  output = ["type=cacheonly"]
  args = {
    GOLANGCI_FROM_SOURCE = "true"
  }
}

target "validate-dockerfile" {
  matrix = {
    dockerfile = [
      "Dockerfile",
      "./hack/dockerfiles/lint.Dockerfile",
    ]
  }
  name = "validate-dockerfile-${md5(dockerfile)}"
  dockerfile = dockerfile
  call = "check"
}

target "lint-gopls" {
    inherits = [ "lint" ]
    target = "gopls-analyze"
}