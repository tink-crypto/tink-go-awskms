workspace(name = "tink_go_awskms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "278b7ff5a826f3dc10f04feaf0b70d48b68748ccd512d7f98bf442077f043fe3",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.41.0/rules_go-v0.41.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.41.0/rules_go-v0.41.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "d3fa66a39028e97d76f9e2db8f1b0c11c099e8e01bf363a923074784e451f809",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.33.0/bazel-gazelle-v0.33.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.33.0/bazel-gazelle-v0.33.0.tar.gz",
    ],
)

# Tink Go AWS KMS Deps.
load("@bazel_gazelle//:deps.bzl", "go_repository", "gazelle_dependencies")

# This is needed because Gazelle fetches golang.org/x/tools@v0.1.12 for this project, while
# io_bazel_rules_go requires golang.org/x/tools@v0.7.0 [2].
#
# [1] https://github.com/tink-crypto/tink-go-awskms/blob/e8e21693ac1fe8ad9c3a9bb2448e351b76b1f96b/deps.bzl#L145
# [2] https://github.com/bazelbuild/rules_go/blob/58534a2cda8e546a4dec6ea9c6b64eb0bfe824dd/go/private/repositories.bzl#L66
go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:W4OVu8VVOaIO0yzWMNdepAulS7YfoS3Zabrm8DOXXU4=",
    version = "v0.7.0",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

load("//:deps.bzl", "tink_go_awskms_dependencies")

# gazelle:repository_macro deps.bzl%tink_go_awskms_dependencies
tink_go_awskms_dependencies()

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.20.10",
)

gazelle_dependencies()
