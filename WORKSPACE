workspace(name = "tink_go_awskms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Release from 2023-12-21
http_archive(
    name = "io_bazel_rules_go",
    integrity = "sha256-gKmCd60TEdrNg3+bFttiiHcC6fHRxMn3ltASGkbI4YQ=",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
    ],
)

# Release from 2023-12-21
http_archive(
    name = "bazel_gazelle",
    integrity = "sha256-MpOL2hbmcABjA1R5Bj2dJMYO2o15/Uc5Vj9Q0zHLMgk=",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz",
    ],
)

# Tink Go AWS KMS Deps.
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

load("//:deps.bzl", "tink_go_awskms_dependencies")

# gazelle:repository_macro deps.bzl%tink_go_awskms_dependencies
tink_go_awskms_dependencies()

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.21.8",
)

gazelle_dependencies()
